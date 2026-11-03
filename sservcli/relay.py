"""Bounded socket/channel relay with half-close and explicit cancellation."""
import contextlib
import socket
import threading


def close_stream(stream):
    with contextlib.suppress(OSError, EOFError):
        stream.shutdown(socket.SHUT_RDWR)
    with contextlib.suppress(OSError, EOFError):
        stream.close()


def relay(left, right, stopping):
    failed = threading.Event()

    def pump(source, destination):
        try:
            while data := source.recv(32768):
                destination.sendall(data)
        except (OSError, EOFError):
            failed.set()
        finally:
            with contextlib.suppress(OSError, EOFError):
                destination.shutdown(socket.SHUT_WR)

    workers = [threading.Thread(target=pump, args=(left, right), daemon=True),
               threading.Thread(target=pump, args=(right, left), daemon=True)]
    try:
        for worker in workers:
            worker.start()
        while any(worker.is_alive() for worker in workers):
            if stopping.wait(0.1) or failed.is_set():
                break
    finally:
        close_stream(left)
        close_stream(right)
        for worker in workers:
            worker.join(timeout=2)
