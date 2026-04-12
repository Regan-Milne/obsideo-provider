package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Regan-Milne/obsideo-provider/config"
)

// ANSI color helpers
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
)

func cprint(msg string)  { fmt.Println(msg) }
func cok(msg string)     { fmt.Printf("%s✓%s %s\n", green, reset, msg) }
func cinfo(msg string)   { fmt.Printf("%s→%s %s\n", cyan, reset, msg) }
func cwarn(msg string)   { fmt.Printf("%s!%s %s\n", yellow, reset, msg) }
func cerr(msg string)    { fmt.Printf("%s✗%s %s\n", red, reset, msg) }
func cdim(msg string)    { fmt.Printf("%s%s%s\n", dim, msg, reset) }
func cheader(msg string) { fmt.Printf("\n%s%s%s%s\n", bold, blue, msg, reset) }

func formatBytesColor(b int64) string {
	switch {
	case b >= 1_000_000_000:
		return fmt.Sprintf("%.2f GB", float64(b)/1e9)
	case b >= 1_000_000:
		return fmt.Sprintf("%.2f MB", float64(b)/1e6)
	case b >= 1_000:
		return fmt.Sprintf("%.2f KB", float64(b)/1e3)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

type repl struct {
	cfg    *config.Config
	client *http.Client
}

func newREPL(cfg *config.Config) *repl {
	return &repl{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}}
}

func (r *repl) url(path string) string {
	return strings.TrimRight(r.cfg.CoordinatorURL, "/") + path
}

func (r *repl) get(path string) ([]byte, error) {
	resp, err := r.client.Get(r.url(path))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, body)
	}
	return body, nil
}

func (r *repl) post(path, payload string) ([]byte, int, error) {
	resp, err := r.client.Post(r.url(path), "application/json", strings.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

// ── commands ────────────────────────────────────────────────────────────────

func (r *repl) cmdHelp() {
	cheader("Data Farmer -- available commands")
	cmds := []struct{ cmd, desc string }{
		{"help", "show this help"},
		{"info", "farm status, storage, earnings"},
		{"harvest", "claim accrued AKT rewards"},
		{"objects", "list stored objects with sizes"},
		{"score", "explain your score and what affects it"},
		{"wallet", "show or update wallet address"},
		{"health", "check coordinator connection"},
		{"quit", "exit"},
	}
	for _, c := range cmds {
		fmt.Printf("  %s%-12s%s %s%s%s\n", cyan, c.cmd, reset, dim, c.desc, reset)
	}
}

func (r *repl) cmdHealth() {
	resp, err := r.client.Get(r.url("/health"))
	if err != nil {
		cerr("cannot reach coordinator: " + err.Error())
		return
	}
	defer resp.Body.Close()
	var h struct{ Status string `json:"status"` }
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &h)
	if h.Status == "ok" {
		cok("coordinator healthy")
	} else {
		cwarn("unexpected response: " + string(body))
	}
}

func (r *repl) cmdInfo() {
	pid := r.cfg.ProviderID

	// Balance
	balBody, err := r.get("/internal/providers/" + pid + "/balance")
	if err != nil {
		cerr("could not fetch balance: " + err.Error())
		return
	}
	var bal struct {
		AccruedUsdMicros        int64   `json:"accrued_usd_micros"`
		LockedUsdMicros         int64   `json:"locked_usd_micros"`
		LifetimeEarnedUsdMicros int64   `json:"lifetime_earned_usd_micros"`
		LifetimePaidUAKT        int64   `json:"lifetime_paid_uakt"`
		Score                   float64 `json:"score"`
	}
	json.Unmarshal(balBody, &bal)

	// Usage
	var totalBytes int64
	var objectCount int
	if uBody, err := r.get("/internal/providers/" + pid + "/usage"); err == nil {
		var usage struct {
			Count int `json:"count"`
			Usage []struct{ BytesHeld int64 `json:"bytes_held"` } `json:"usage"`
		}
		json.Unmarshal(uBody, &usage)
		objectCount = usage.Count
		for _, u := range usage.Usage {
			totalBytes += u.BytesHeld
		}
	}

	cheader("Farm Status")
	fmt.Printf("  %sfarm id%s    %s%s%s\n", dim, reset, cyan, pid, reset)

	scoreColor := green
	if bal.Score < 0.5 {
		scoreColor = red
	} else if bal.Score < 0.8 {
		scoreColor = yellow
	}
	fmt.Printf("  %sscore%s      %s%.0f%%%s\n", dim, reset, scoreColor, bal.Score*100, reset)
	cprint("")

	cheader("Storage")
	fmt.Printf("  %sobjects%s    %s%d%s\n", dim, reset, cyan, objectCount, reset)
	fmt.Printf("  %ssize%s       %s%s%s\n", dim, reset, cyan, formatBytesColor(totalBytes), reset)
	cprint("")

	// Fetch AKT rate for USD -> AKT conversion
	var aktRate float64
	if oBody, err := r.get("/oracle"); err == nil {
		var oracle struct{ AktUsd float64 `json:"akt_usd"` }
		json.Unmarshal(oBody, &oracle)
		aktRate = oracle.AktUsd
	}

	cheader("Earnings")
	accruedUsd := float64(bal.AccruedUsdMicros) / 1e6
	if bal.AccruedUsdMicros > 0 && aktRate > 0 {
		accruedAkt := accruedUsd / aktRate
		fmt.Printf("  %sclaimable%s  %s%.6f AKT%s  %s($%.6f USD)%s\n",
			dim, reset, green, accruedAkt, reset, dim, accruedUsd, reset)
	} else if bal.AccruedUsdMicros > 0 {
		fmt.Printf("  %sclaimable%s  %s$%.6f USD%s\n", dim, reset, green, accruedUsd, reset)
	} else {
		fmt.Printf("  %sclaimable%s  %s0 AKT%s\n", dim, reset, dim, reset)
	}
	if bal.LockedUsdMicros > 0 {
		lockedUsd := float64(bal.LockedUsdMicros) / 1e6
		if aktRate > 0 {
			fmt.Printf("  %slocked%s     %s%.6f AKT%s %s(harvest pending)%s\n",
				dim, reset, yellow, lockedUsd/aktRate, reset, dim, reset)
		} else {
			fmt.Printf("  %slocked%s     %s$%.6f USD%s %s(harvest pending)%s\n",
				dim, reset, yellow, lockedUsd, reset, dim, reset)
		}
	}
	if bal.LifetimePaidUAKT > 0 {
		fmt.Printf("  %sharvested%s  %s%.6f AKT%s\n",
			dim, reset, green, float64(bal.LifetimePaidUAKT)/1e6, reset)
	}
	if aktRate > 0 {
		fmt.Printf("  %sAKT rate%s   %s$%.4f%s\n", dim, reset, dim, aktRate, reset)
	}
	cprint("")

	// Wallet
	if r.cfg.WalletAddress != "" {
		fmt.Printf("  %swallet%s     %s%s%s\n", dim, reset, cyan, r.cfg.WalletAddress, reset)
	} else {
		fmt.Printf("  %swallet%s     %snot set%s\n", dim, reset, yellow, reset)
		cdim("             set wallet_address in config.yaml to harvest")
	}

	// Withdrawals
	if wBody, err := r.get("/internal/providers/" + pid + "/withdrawals"); err == nil {
		var wResult struct {
			Withdrawals []struct {
				ID      string `json:"id"`
				Status  string `json:"status"`
				NetUAkt int64  `json:"net_uakt"`
			} `json:"withdrawals"`
		}
		json.Unmarshal(wBody, &wResult)
		if len(wResult.Withdrawals) > 0 {
			cheader("Harvest History")
			for _, w := range wResult.Withdrawals {
				statusColor := dim
				statusText := w.Status
				switch w.Status {
				case "locked":
					statusColor = yellow
					statusText = "queued"
				case "broadcast":
					statusColor = yellow
					statusText = "processing"
				case "confirmed":
					statusColor = green
					statusText = "harvested"
				case "failed":
					statusColor = red
					statusText = "failed"
				}
				fmt.Printf("  %s%.6f AKT%s  %s%s%s\n",
					dim, float64(w.NetUAkt)/1e6, reset, statusColor, statusText, reset)
			}
		}
	}
}

func (r *repl) cmdObjects() {
	pid := r.cfg.ProviderID
	uBody, err := r.get("/internal/providers/" + pid + "/usage")
	if err != nil {
		cerr("could not fetch usage: " + err.Error())
		return
	}
	var usage struct {
		Count int `json:"count"`
		Usage []struct {
			ObjectID  string `json:"object_id"`
			BytesHeld int64  `json:"bytes_held"`
		} `json:"usage"`
	}
	json.Unmarshal(uBody, &usage)

	if usage.Count == 0 {
		cdim("  (no objects stored)")
		return
	}

	cheader(fmt.Sprintf("Stored Objects (%d)", usage.Count))
	for _, u := range usage.Usage {
		id := u.ObjectID
		if len(id) > 16 {
			id = id[:16]
		}
		fmt.Printf("  %s%s%s  %s%s%s\n", cyan, id, reset, dim, formatBytesColor(u.BytesHeld), reset)
	}
}

func (r *repl) cmdScore() {
	pid := r.cfg.ProviderID
	balBody, err := r.get("/internal/providers/" + pid + "/balance")
	if err != nil {
		cerr("could not fetch balance: " + err.Error())
		return
	}
	var bal struct{ Score float64 `json:"score"` }
	json.Unmarshal(balBody, &bal)

	cheader("Score Details")
	scoreColor := green
	if bal.Score < 0.5 {
		scoreColor = red
	} else if bal.Score < 0.8 {
		scoreColor = yellow
	}
	fmt.Printf("  %scurrent%s    %s%.0f%%%s\n\n", dim, reset, scoreColor, bal.Score*100, reset)

	cdim("  Your score is a direct multiplier on earnings.")
	cdim("  Score 80% = 80% of the full storage rate.")
	cdim("")
	cdim("  Score goes UP when you pass proof-of-retrievability challenges.")
	cdim("  Score goes DOWN when challenges fail (data unavailable).")
	cdim("  Keep your provider online and responsive to maintain 100%.")
}

func (r *repl) cmdWallet() {
	if r.cfg.WalletAddress != "" {
		cinfo("wallet: " + r.cfg.WalletAddress)
		cdim("  to change, edit wallet_address in config.yaml")
	} else {
		cwarn("no wallet set")
		cdim("  add this to your config.yaml:")
		cprint("")
		fmt.Printf("    %swallet_address: \"akash1...\"%s\n", cyan, reset)
	}
}

func (r *repl) cmdHarvest() {
	if r.cfg.WalletAddress == "" {
		cwarn("no wallet_address set in config.yaml")
		cdim("  add your AKT address to start harvesting:")
		cprint("")
		fmt.Printf("    %swallet_address: \"akash1...\"%s\n", cyan, reset)
		return
	}

	// Sync wallet via heartbeat
	r.post("/internal/providers/"+r.cfg.ProviderID+"/heartbeat",
		fmt.Sprintf(`{"wallet_address":"%s"}`, r.cfg.WalletAddress))

	// Request withdrawal
	body, status, err := r.post("/internal/providers/"+r.cfg.ProviderID+"/withdraw", "{}")
	if err != nil {
		cerr("could not reach coordinator: " + err.Error())
		return
	}

	if status != http.StatusOK {
		var errResp struct{ Error string `json:"error"` }
		json.Unmarshal(body, &errResp)
		switch {
		case strings.Contains(errResp.Error, "no accrued balance"):
			cinfo("nothing to harvest yet -- keep farming!")
			cdim("  rewards accrue daily based on stored data and score")
		case strings.Contains(errResp.Error, "too small to cover gas"):
			cinfo("accrued balance is below the gas fee threshold")
			cdim("  keep farming -- rewards will grow with more data and time")
		default:
			cerr(errResp.Error)
		}
		return
	}

	var w struct {
		ID            string  `json:"id"`
		NetUAkt       int64   `json:"net_uakt"`
		AktRateUsd    float64 `json:"akt_rate_usd"`
		NetUsdMicros  int64   `json:"net_usd_micros"`
		WalletAddress string  `json:"wallet_address"`
	}
	json.Unmarshal(body, &w)

	cok("harvest submitted!")
	cprint("")
	fmt.Printf("  %samount%s   %s%.6f AKT%s ($%.6f USD)\n",
		dim, reset, green, float64(w.NetUAkt)/1e6, reset, float64(w.NetUsdMicros)/1e6)
	fmt.Printf("  %srate%s     $%.4f / AKT\n", dim, reset, w.AktRateUsd)
	fmt.Printf("  %swallet%s   %s\n", dim, reset, w.WalletAddress)
	cprint("")
	cdim("  queued for human-verified settlement (up to 24 hours)")
	cdim("  run 'info' to check status")
}

// ── REPL loop ───────────────────────────────────────────────────────────────

func runREPL(cfg *config.Config) {
	r := newREPL(cfg)

	fmt.Printf("%s%s", bold, green)
	fmt.Println(`
  ██████╗  █████╗ ████████╗ █████╗
  ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗
  ██║  ██║███████║   ██║   ███████║
  ██║  ██║██╔══██║   ██║   ██╔══██║
  ██████╔╝██║  ██║   ██║   ██║  ██║
  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
  ███████╗ █████╗ ██████╗ ███╗   ███╗███████╗██████╗
  ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔══██╗
  █████╗  ███████║██████╔╝██╔████╔██║█████╗  ██████╔╝
  ██╔══╝  ██╔══██║██╔══██╗██║╚██╔╝██║██╔══╝  ██╔══██╗
  ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝`)
	fmt.Printf("%s", reset)
	fmt.Printf("  %s%sby obsideo%s\n\n", dim, cyan, reset)
	fmt.Printf("  %stype %shelp%s%s to see commands%s\n\n", dim, reset, cyan, dim, reset)

	r.cmdHealth()
	cprint("")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("%sdatafarmer%s %s>%s ", bold, reset, dim, reset)
		if !scanner.Scan() {
			cprint("\nbye.")
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch strings.ToLower(line) {
		case "help", "h", "?":
			r.cmdHelp()
		case "info", "i", "status":
			r.cmdInfo()
		case "harvest":
			r.cmdHarvest()
		case "objects", "ls", "list":
			r.cmdObjects()
		case "score":
			r.cmdScore()
		case "wallet":
			r.cmdWallet()
		case "health", "ping":
			r.cmdHealth()
		case "quit", "exit", "q":
			cprint("bye.")
			return
		default:
			cerr(fmt.Sprintf("unknown command %q -- type help for a list", line))
		}
		cprint("")
	}
}
