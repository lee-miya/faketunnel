package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"faketunnel/internal/config"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	switch args[0] {
	case "version", "-version", "--version":
		fmt.Println(version)
		return 0
	case "init":
		if err := runInit(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "faketunnel: %v\n", err)
			return 1
		}
		return 0
	case "allowlist":
		if err := runAllowlist(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "faketunnel: %v\n", err)
			return 1
		}
		return 0
	case "denylist", "ban":
		if err := runDenylist(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "faketunnel: %v\n", err)
			return 1
		}
		return 0
	case "status":
		if err := runStatus(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "faketunnel: %v\n", err)
			return 1
		}
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `fakeTunnel CLI — 初始化配置、管理 Edge allowlist / denylist 与状态

用法:
  faketunnel init            [-dir DIR] [-edge HOST] [-http 8080:3000] [-tcp 2222]
  faketunnel allowlist list  [-admin URL] [-token TOKEN] [-token-file PATH]
  faketunnel allowlist add   <cidr>... [-admin URL] [-token TOKEN]
  faketunnel allowlist add-self [-admin URL] [-token TOKEN]
  faketunnel allowlist rm    <cidr>... [-admin URL] [-token TOKEN]
  faketunnel allowlist set   <cidr>... [-admin URL] [-token TOKEN]
  faketunnel denylist list   [-admin URL] [-token TOKEN]
  faketunnel denylist rm     <ip>... [-admin URL] [-token TOKEN]
  faketunnel status          [-admin URL] [-token TOKEN]
  faketunnel version

环境变量:
  FAKETUNNEL_ADMIN   Admin API 根地址（默认 http://127.0.0.1:9090；公网请用 https://）
  FAKETUNNEL_TOKEN   Admin Bearer token（也可放在 ./admin.token）

`)
}

type client struct {
	base  string
	token string
	http  *http.Client
	actor string
}

func newClient(fs *flag.FlagSet, args []string) (*client, []string, error) {
	adminURL := fs.String("admin", envOr("FAKETUNNEL_ADMIN", "http://127.0.0.1:9090"), "Admin API base URL")
	token := fs.String("token", os.Getenv("FAKETUNNEL_TOKEN"), "Admin Bearer token")
	tokenFile := fs.String("token-file", "", "read admin token from file")
	actor := fs.String("actor", "", "optional X-Admin-Actor audit label")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verify (self-signed Admin HTTPS)")
	positional, err := parseFlagSet(fs, args)
	if err != nil {
		return nil, nil, err
	}
	tok := strings.TrimSpace(*token)
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return nil, nil, err
		}
		tok = strings.TrimSpace(string(data))
	}
	if tok == "" {
		tok = config.DiscoverAdminToken()
	}
	if tok == "" {
		return nil, nil, fmt.Errorf("admin token required (-token, -token-file, FAKETUNNEL_TOKEN, or admin.token file)")
	}
	hc := &http.Client{Timeout: 15 * time.Second}
	if *insecure {
		hc.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}
	return &client{
		base:  strings.TrimRight(strings.TrimSpace(*adminURL), "/"),
		token: tok,
		http:  hc,
		actor: strings.TrimSpace(*actor),
	}, positional, nil
}

func parseFlagSet(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) > 0 {
			positional = append(positional, args[0])
			args = args[1:]
		}
	}
	return positional, nil
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func runAllowlist(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("allowlist requires subcommand: list|add|add-self|rm|set")
	}
	sub := args[0]
	fs := flag.NewFlagSet("allowlist "+sub, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cli, rest, err := newClient(fs, args[1:])
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		cidrs, err := cli.getAllowlist()
		if err != nil {
			return err
		}
		for _, c := range cidrs {
			fmt.Println(c)
		}
		return nil
	case "add-self", "addself", "me":
		return cli.addSelf()
	case "add":
		if len(rest) == 0 {
			return fmt.Errorf("usage: faketunnel allowlist add <cidr>...")
		}
		return cli.postAllowlist(rest)
	case "rm", "remove", "delete":
		if len(rest) == 0 {
			return fmt.Errorf("usage: faketunnel allowlist rm <cidr>...")
		}
		return cli.deleteAllowlist(rest)
	case "set", "replace":
		if len(rest) == 0 {
			return fmt.Errorf("usage: faketunnel allowlist set <cidr>...")
		}
		return cli.putAllowlist(rest)
	default:
		return fmt.Errorf("unknown allowlist subcommand %q", sub)
	}
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cli, _, err := newClient(fs, args)
	if err != nil {
		return err
	}
	body, err := cli.do(http.MethodGet, "/v1/status", nil)
	if err != nil {
		return err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		fmt.Println(string(body))
		return nil
	}
	fmt.Println(pretty.String())
	return nil
}

type allowlistDTO struct {
	CIDRs []string `json:"cidrs"`
}

func (c *client) getAllowlist() ([]string, error) {
	body, err := c.do(http.MethodGet, "/v1/allowlist", nil)
	if err != nil {
		return nil, err
	}
	var dto allowlistDTO
	if err := json.Unmarshal(body, &dto); err != nil {
		return nil, err
	}
	return dto.CIDRs, nil
}

func (c *client) putAllowlist(cidrs []string) error {
	payload, _ := json.Marshal(allowlistDTO{CIDRs: cidrs})
	body, err := c.do(http.MethodPut, "/v1/allowlist", payload)
	if err != nil {
		return err
	}
	return printCIDRs(body)
}

func (c *client) postAllowlist(cidrs []string) error {
	payload, _ := json.Marshal(allowlistDTO{CIDRs: cidrs})
	body, err := c.do(http.MethodPost, "/v1/allowlist", payload)
	if err != nil {
		return err
	}
	return printCIDRs(body)
}

func (c *client) deleteAllowlist(cidrs []string) error {
	payload, _ := json.Marshal(allowlistDTO{CIDRs: cidrs})
	body, err := c.do(http.MethodDelete, "/v1/allowlist", payload)
	if err != nil {
		return err
	}
	return printCIDRs(body)
}

func runDenylist(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("denylist requires subcommand: list|rm")
	}
	sub := args[0]
	fs := flag.NewFlagSet("denylist "+sub, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cli, rest, err := newClient(fs, args[1:])
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		body, err := cli.do(http.MethodGet, "/v1/denylist", nil)
		if err != nil {
			return err
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, body, "", "  "); err != nil {
			fmt.Println(string(body))
			return nil
		}
		fmt.Println(pretty.String())
		return nil
	case "rm", "remove", "delete", "unban":
		if len(rest) == 0 {
			return fmt.Errorf("usage: faketunnel denylist rm <ip>...")
		}
		payload, _ := json.Marshal(map[string]any{"ips": rest})
		body, err := cli.do(http.MethodDelete, "/v1/denylist", payload)
		if err != nil {
			return err
		}
		fmt.Println(string(body))
		return nil
	default:
		return fmt.Errorf("unknown denylist subcommand %q", sub)
	}
}

func (c *client) addSelf() error {
	body, err := c.do(http.MethodPost, "/v1/allowlist/self", []byte("{}"))
	if err != nil {
		return err
	}
	return printCIDRs(body)
}

func printCIDRs(body []byte) error {
	var dto allowlistDTO
	if err := json.Unmarshal(body, &dto); err != nil {
		fmt.Println(string(body))
		return nil
	}
	for _, c := range dto.CIDRs {
		fmt.Println(c)
	}
	return nil
}

func (c *client) do(method, path string, payload []byte) ([]byte, error) {
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if c.actor != "" {
		req.Header.Set("X-Admin-Actor", c.actor)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return body, nil
}
