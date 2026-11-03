"""Real ssh/sshd password-forwarding tests using private NSS fixtures, no root."""
import contextlib
import ctypes.util
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from sservcli.askpass import environment
from sservcli.tunnel import Tunnel

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('provision', ROOT / 'server/sservcli_server.py')
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def wait_for(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError('Timed out waiting for native OpenSSH state')


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        value = self.request.recv(65536)
        if value:
            self.request.sendall(self.server.tag + value)


class HalfCloseEcho(socketserver.BaseRequestHandler):
    def handle(self):
        values = []
        while value := self.request.recv(32768):
            values.append(value)
        self.request.sendall(self.server.tag + b''.join(values))


@unittest.skipUnless(os.name == 'posix' and os.environ.get('SSERVCLI_SSH_TESTS') == '1', 'Run make integration on Linux')
class NativeTokenSshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = os.environ.get('SSERVCLI_NSS_WRAPPER') or ctypes.util.find_library('nss_wrapper')
        if not cls.wrapper:
            raise unittest.SkipTest('Install libnss-wrapper or set SSERVCLI_NSS_WRAPPER to its library; no production users are modified')
        cls.echoes = []
        for index, handler in enumerate((Echo, Echo, HalfCloseEcho)):
            echo = socketserver.ThreadingTCPServer(('127.0.0.1', 0), handler)
            echo.daemon_threads = True
            echo.tag = f'service-{index}:'.encode()
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            cls.addClassCleanup(echo.server_close)
            cls.addClassCleanup(echo.shutdown)
            cls.echoes.append(echo)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sservcli-native-token-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.secret = 'Ab1Cd2E3'
        self.user = 'sservcli_token_fixture'
        self.password_file = self.directory / 'passwd'
        self.set_password(self.secret)
        (self.directory / 'group').write_text(f'sservcli_fixture:x:{os.getgid()}:\n')
        self.daemon_env = {**os.environ, 'LD_PRELOAD': self.wrapper, 'NSS_WRAPPER_PASSWD': str(self.password_file),
                           'NSS_WRAPPER_GROUP': str(self.directory / 'group')}
        for name in ('host', 'wrong_host'):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.directory / name)], check=True)
        self.port = free_port()
        services = []
        for index, echo in enumerate(self.echoes):
            services.append({'id': f'svc{index}', 'name': f'Service {index}', 'kind': 'tcp', 'remote_host': '127.0.0.1',
                             'remote_port': echo.server_address[1], 'local_port': free_port()})
        self.profile = {'version': 2, 'name': 'Native OpenSSH token test', 'ssh': {
            'host': '127.0.0.1', 'port': self.port, 'user': self.user, 'host_public_key': (self.directory / 'host.pub').read_text().strip()},
            'services': services, 'reconnect': {'enabled': True, 'max_attempts': 2, 'initial_delay_secs': 1, 'max_delay_secs': 2}}
        allowed = [f"127.0.0.1:{service['remote_port']}" for service in services]
        config = self.directory / 'sshd_config'
        config.write_text(f'Port {self.port}\nListenAddress 127.0.0.1\nHostKey {self.directory}/host\n'
                          f'PidFile {self.directory}/sshd.pid\nUsePAM no\nStrictModes no\nLogLevel VERBOSE\n' + provision.policy(self.user, allowed, 'token'))
        self.log_path = self.directory / 'sshd.log'
        log = self.log_path.open('w')
        self.addCleanup(log.close)
        self.daemon = subprocess.Popen([shutil.which('sshd') or '/usr/sbin/sshd', '-D', '-e', '-f', str(config)],
                                       env=self.daemon_env, stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
        self.addCleanup(self.stop_daemon)
        wait_for(lambda: 'Server listening' in self.log_path.read_text())
        self.tunnel = Tunnel()
        self.addCleanup(self.tunnel.disconnect)

    def set_password(self, token=None, *, locked=False):
        if locked:
            hashed = '!'
        else:
            hashed = subprocess.run(['openssl', 'passwd', '-6', '-stdin'], input=token, text=True, capture_output=True, check=True).stdout.strip()
        previous = self.password_file.stat().st_mtime if self.password_file.exists() else time.time()
        self.password_file.write_text(f'{self.user}:{hashed}:{os.getuid()}:{os.getgid()}:Private fixture:{self.directory}:/usr/sbin/nologin\n')
        # NSS wrapper may cache timestamps at one-second resolution.
        os.utime(self.password_file, (previous + 2, previous + 2))

    def stop_daemon(self):
        if self.daemon.poll() is None:
            os.killpg(self.daemon.pid, signal.SIGTERM)
            self.daemon.wait(timeout=5)

    def connect(self, token=None, expected='connected'):
        self.tunnel.connect(self.profile, token=token or self.secret)
        wait_for(lambda: self.tunnel.snapshot()['status'] in ('connected', 'failed'))
        state = self.tunnel.snapshot()
        self.assertEqual(state['status'], expected, state['logs'] + [self.log_path.read_text()])
        return state

    def roundtrip(self, index=0, data=b'ping'):
        with socket.create_connection(('127.0.0.1', self.profile['services'][index]['local_port']), timeout=3) as stream:
            stream.sendall(data)
            stream.shutdown(socket.SHUT_WR)
            result = []
            while value := stream.recv(65536):
                result.append(value)
        self.assertEqual(b''.join(result), f'service-{index}:'.encode() + data)

    def test_native_ssh_multiplexes_all_services_and_releases_the_ports(self):
        self.connect()
        for index in range(3):
            self.roundtrip(index)
        self.assertEqual(self.log_path.read_text().count('Accepted password'), 1)
        self.tunnel.disconnect()
        for service in self.profile['services']:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(('127.0.0.1', service['local_port']))

    def test_large_request_half_close_preserves_the_response(self):
        self.connect()
        self.roundtrip(2, os.urandom(256 * 1024))

    def test_password_is_case_sensitive_and_bad_tokens_are_not_retried_or_logged(self):
        state = self.connect(self.secret.swapcase(), expected='failed')
        self.assertIn('Shared token rejected', state['message'])
        self.assertEqual(state['attempt'], 0)
        self.assertNotIn(self.secret, '\n'.join(state['logs']))
        self.assertNotIn(self.secret.swapcase(), '\n'.join(state['logs']))
        self.assertEqual(self.log_path.read_text().count('Failed password'), 1)

    def test_rotating_the_native_password_invalidates_the_old_token(self):
        self.connect()
        self.tunnel.disconnect()
        self.set_password('Z9y8X7w6')
        self.connect(expected='failed')
        self.tunnel.disconnect()
        self.connect('Z9y8X7w6')
        self.roundtrip()

    def test_locking_the_native_account_revokes_the_token(self):
        self.set_password(locked=True)
        self.connect(expected='failed')
        self.assertNotIn('Accepted password', self.log_path.read_text())

    def test_strict_host_verification_stops_before_password_authentication(self):
        self.profile['ssh']['host_public_key'] = (self.directory / 'wrong_host.pub').read_text().strip()
        state = self.connect(expected='failed')
        self.assertIn('HOST IDENTIFICATION HAS CHANGED', '\n'.join(state['logs']))
        self.assertNotIn('Accepted password', self.log_path.read_text())
        self.assertNotIn('Failed password', self.log_path.read_text())

    def test_fallback_addresses_reuse_the_same_host_key(self):
        self.profile['ssh'].update(host='127.0.0.2', fallback_hosts=['127.0.0.1'])
        state = self.connect()
        self.assertEqual(state['active_host'], '127.0.0.1')
        self.roundtrip()

    def test_reconnect_still_spawns_the_native_ssh_program(self):
        real = subprocess.Popen
        children = []
        def spawn(argv, *args, **kwargs):
            child = real(argv, *args, **kwargs)
            if '-N' in argv:
                children.append(child)
            return child
        with patch('sservcli.tunnel.subprocess.Popen', side_effect=spawn):
            self.connect()
            self.assertEqual(len(children), 1)
            children[0].terminate()
            wait_for(lambda: self.log_path.read_text().count('Accepted password') >= 2 and self.tunnel.snapshot()['status'] == 'connected')
            self.assertEqual(len(children), 2)
            self.roundtrip()

    def test_shell_and_remote_forwarding_remain_denied(self):
        known = self.directory / 'known_hosts'
        known.write_text(f'[127.0.0.1]:{self.port} ' + self.profile['ssh']['host_public_key'] + '\n')
        values = environment(self.secret, self.directory)
        base = ['ssh', '-F', 'none', '-n', '-T', '-p', str(self.port), '-l', self.user,
                '-o', 'BatchMode=no', '-o', 'PreferredAuthentications=password', '-o', 'NumberOfPasswordPrompts=1',
                '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile="{known}"', '-o', 'ExitOnForwardFailure=yes']
        shell = subprocess.run([*base, '127.0.0.1', 'true'], env=values, capture_output=True, timeout=8)
        self.assertNotEqual(shell.returncode, 0)
        remote = subprocess.run([*base, '-N', '-R', f'127.0.0.1:{free_port()}:127.0.0.1:80', '127.0.0.1'], env=values, capture_output=True, timeout=8)
        self.assertNotEqual(remote.returncode, 0)
        self.assertIn(b'remote port forwarding failed', remote.stderr)

    def test_unlisted_destination_is_blocked_by_system_sshd(self):
        self.profile['services'][0]['remote_port'] = 1
        self.connect()
        with socket.create_connection(('127.0.0.1', self.profile['services'][0]['local_port']), timeout=3) as stream:
            stream.sendall(b'forbidden')
            with contextlib.suppress(ConnectionResetError):
                self.assertEqual(stream.recv(1024), b'')


if __name__ == '__main__':
    unittest.main()
