package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func Main(args []string) error {
	// OpenSSH invokes this same binary as its askpass executable. The value is
	// scoped to the SSH child's environment and never appears in its arguments.
	if os.Getenv("SSERVCLI_ASKPASS_MODE") == "1" {
		token := os.Getenv("SSERVCLI_ASKPASS_TOKEN")
		if !tokenPattern.MatchString(token) || os.Getenv("SSH_ASKPASS_PROMPT") == "confirm" || os.Getenv("SSH_ASKPASS_PROMPT") == "none" {
			return errors.New("askpass refused")
		}
		_, err := fmt.Fprintln(os.Stdout, token)
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	base := filepath.Dir(exe)
	defaultLaunch := len(args) == 0
	command := "start"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}
	if command == "help" || command == "--help" || command == "-h" {
		fmt.Println("sservcli [start|run|stop|status|list|check|connect|reconnect|disconnect|ui|open] [options]\nReads services.json and .token beside the executable.\nstart: background client and local management page at http://127.0.0.1:8000\nrun: foreground client with the same page; connect: foreground SSH only\nOptions: --config FILE --token-file FILE --state-dir DIR --web-port 8000\nopen: add --service SERVICE_ID; list/status: add --json")
		return nil
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	o := options{}
	flags.StringVar(&o.Config, "config", filepath.Join(base, "services.json"), "service profile")
	flags.StringVar(&o.Token, "token-file", filepath.Join(base, ".token"), "8-character token file")
	flags.StringVar(&o.Directory, "state-dir", filepath.Join(base, ".sservcli"), "private runtime directory")
	flags.IntVar(&o.WebPort, "web-port", 8000, "loopback management port")
	outputJSON := flags.Bool("json", false, "output JSON")
	serviceID := flags.String("service", "", "service ID to open")
	if err = flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return errors.New("unexpected arguments")
	}
	if o.WebPort < 1024 || o.WebPort > 65535 {
		return errors.New("management port must be 1024-65535")
	}
	o.Config, err = filepath.Abs(o.Config)
	if err != nil {
		return err
	}
	o.Token, err = filepath.Abs(o.Token)
	if err != nil {
		return err
	}
	o.Directory, err = filepath.Abs(o.Directory)
	if err != nil {
		return err
	}
	switch command {
	case "run":
		return runDaemon(o)
	case "start":
		if err := startDaemon(o); err != nil {
			return err
		}
		if defaultLaunch {
			_ = openUI(o)
		}
		return nil
	case "ui":
		return openUI(o)
	case "status":
		data, err := controlRequest(o, "status", http.MethodGet)
		if err != nil {
			return err
		}
		if *outputJSON {
			fmt.Println(string(data))
			return nil
		}
		var status statusView
		if err = json.Unmarshal(data, &status); err != nil {
			return err
		}
		fmt.Printf("%s: %s\n%s\n", status.Status, status.Name, status.Message)
		if info, err := readRuntime(o); err == nil {
			fmt.Printf("Management: http://127.0.0.1:%d\n", info.Port)
		}
		return nil
	case "stop":
		if _, err = controlRequest(o, "stop", http.MethodPost); err != nil {
			return err
		}
		for i := 0; i < 150; i++ {
			if _, err := os.Stat(filepath.Join(o.Directory, "run.json")); os.IsNotExist(err) {
				fmt.Println("Client stopped; forwarding ports released.")
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return errors.New("client is still stopping; check status/log")
	case "disconnect":
		_, err = controlRequest(o, "disconnect", http.MethodPost)
		return err
	case "open":
		if *serviceID == "" {
			return errors.New("set --service SERVICE_ID")
		}
		_, err = controlRequest(o, "open?id="+*serviceID, http.MethodPost)
		return err
	case "list", "check", "connect":
		p, err := loadProfile(o.Config)
		if err != nil {
			return err
		}
		if command == "check" {
			fmt.Printf("Valid profile: %s (%d services)\n", p.Name, len(p.Services))
			return nil
		}
		if command == "list" {
			if *outputJSON {
				return json.NewEncoder(os.Stdout).Encode(p.Services)
			}
			for _, s := range p.Services {
				enabled := "enabled"
				if !s.IsEnabled() {
					enabled = "disabled"
				}
				address := s.Endpoint()
				if s.Kind == "web" || s.Kind == "api" {
					address = s.URL()
				}
				fmt.Printf("%-16s %-8s %-36s -> 127.0.0.1:%d\n", s.ID, enabled, address, s.RemotePort)
			}
			return nil
		}
		token := ""
		if p.Version == 2 {
			token, err = readToken(o.Token)
			if err != nil {
				return err
			}
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return newTunnel(os.Stderr).run(ctx, p, token)
	case "reconnect":
		_, err = controlRequest(o, "connect", http.MethodPost)
		return err
	default:
		return fmt.Errorf("unknown command %q (use help)", strings.TrimSpace(command))
	}
}
