package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
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
	case "allowlist":
		if err := runAllowlist(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "mytunnel: %v\n", err)
			return 1
		}
		return 0
	case "status":
		if err := runStatus(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "mytunnel: %v\n", err)
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
	fmt.Fprintf(os.Stderr, `myTunnel CLI — 管理 Edge allowlist 与状态

用法:
  mytunnel allowlist list  [-admin URL] [-token TOKEN] [-token-file PATH]
  mytunnel allowlist add   <cidr>... [-admin URL] [-token TOKEN]
  mytunnel allowlist rm    <cidr>... [-admin URL] [-token TOKEN]
  mytunnel allowlist set   <cidr>... [-admin URL] [-token TOKEN]
  mytunnel status          [-admin URL] [-token TOKEN]
  mytunnel version

环境变量:
  MYTUNNEL_ADMIN   Admin API 根地址（默认 http://127.0.0.1:9090）
  MYTUNNEL_TOKEN   Admin Bearer token

`)
}

type client struct {
	base  string
	token string
	http  *http.Client
	actor string
}

func newClient(fs *flag.FlagSet, args []string) (*client, []string, error) {
	adminURL := fs.String("admin", envOr("MYTUNNEL_ADMIN", "http://127.0.0.1:9090"), "Admin API base URL")
	token := fs.String("token", os.Getenv("MYTUNNEL_TOKEN"), "Admin Bearer token")
	tokenFile := fs.String("token-file", "", "read admin token from file")
	actor := fs.String("actor", "", "optional X-Admin-Actor audit label")
	if err := fs.Parse(args); err != nil {
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
		return nil, nil, fmt.Errorf("admin token required (-token, -token-file, or MYTUNNEL_TOKEN)")
	}
	return &client{
		base:  strings.TrimRight(strings.TrimSpace(*adminURL), "/"),
		token: tok,
		http:  &http.Client{Timeout: 15 * time.Second},
		actor: strings.TrimSpace(*actor),
	}, fs.Args(), nil
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func runAllowlist(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("allowlist requires subcommand: list|add|rm|set")
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
	case "add":
		if len(rest) == 0 {
			return fmt.Errorf("usage: mytunnel allowlist add <cidr>...")
		}
		return cli.postAllowlist(rest)
	case "rm", "remove", "delete":
		if len(rest) == 0 {
			return fmt.Errorf("usage: mytunnel allowlist rm <cidr>...")
		}
		return cli.deleteAllowlist(rest)
	case "set", "replace":
		if len(rest) == 0 {
			return fmt.Errorf("usage: mytunnel allowlist set <cidr>...")
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
