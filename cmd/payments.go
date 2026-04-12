package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Regan-Milne/obsideo-provider/config"
	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "View your farm status, earnings, and storage stats",
	RunE:  runInfo,
}

var harvestCmd = &cobra.Command{
	Use:   "harvest",
	Short: "Harvest your accrued AKT rewards",
	RunE:  runHarvest,
}

func init() {
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(harvestCmd)
}

func loadPaymentConfig() (*config.Config, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, err
	}
	if cfg.ProviderID == "" {
		return nil, fmt.Errorf("provider_id not set in config")
	}
	if cfg.CoordinatorURL == "" {
		return nil, fmt.Errorf("coordinator_url not set in config")
	}
	return cfg, nil
}

func coordinatorURL(cfg *config.Config, path string) string {
	return strings.TrimRight(cfg.CoordinatorURL, "/") + path
}

func runInfo(cmd *cobra.Command, args []string) error {
	cfg, err := loadPaymentConfig()
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Fetch balance
	resp, err := client.Get(coordinatorURL(cfg, "/internal/providers/"+cfg.ProviderID+"/balance"))
	if err != nil {
		return fmt.Errorf("could not reach coordinator: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("coordinator returned %d: %s", resp.StatusCode, body)
	}

	var bal struct {
		AccruedUsdMicros        int64   `json:"accrued_usd_micros"`
		LockedUsdMicros         int64   `json:"locked_usd_micros"`
		LifetimeEarnedUsdMicros int64   `json:"lifetime_earned_usd_micros"`
		LifetimePaidUAKT        int64   `json:"lifetime_paid_uakt"`
		Score                   float64 `json:"score"`
	}
	if err := json.Unmarshal(body, &bal); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	// Fetch usage stats
	var totalBytes int64
	var objectCount int
	uResp, err := client.Get(coordinatorURL(cfg, "/internal/providers/"+cfg.ProviderID+"/usage"))
	if err == nil {
		defer uResp.Body.Close()
		uBody, _ := io.ReadAll(uResp.Body)
		var usage struct {
			Count int `json:"count"`
			Usage []struct {
				BytesHeld int64 `json:"bytes_held"`
			} `json:"usage"`
		}
		if json.Unmarshal(uBody, &usage) == nil {
			objectCount = usage.Count
			for _, u := range usage.Usage {
				totalBytes += u.BytesHeld
			}
		}
	}

	// Print farm status
	fmt.Println()
	fmt.Println("  OBSIDEO DATA FARMER")
	fmt.Println("  -------------------")
	fmt.Printf("  Farm ID:    %s\n", cfg.ProviderID)
	fmt.Printf("  Score:      %.0f%%\n", bal.Score*100)
	fmt.Println()

	// Storage
	fmt.Println("  Storage")
	fmt.Printf("    Objects:  %d\n", objectCount)
	fmt.Printf("    Size:     %s\n", formatBytes(totalBytes))
	fmt.Println()

	// Fetch AKT rate
	var aktRate float64
	oResp, err := client.Get(coordinatorURL(cfg, "/oracle"))
	if err == nil {
		defer oResp.Body.Close()
		oBody, _ := io.ReadAll(oResp.Body)
		var oracle struct{ AktUsd float64 `json:"akt_usd"` }
		json.Unmarshal(oBody, &oracle)
		aktRate = oracle.AktUsd
	}

	// Earnings
	fmt.Println("  Earnings")
	accruedUsd := float64(bal.AccruedUsdMicros) / 1e6
	if bal.AccruedUsdMicros > 0 && aktRate > 0 {
		fmt.Printf("    Claimable: %.6f AKT ($%.6f USD)\n", accruedUsd/aktRate, accruedUsd)
	} else {
		fmt.Printf("    Claimable: $%.6f USD\n", accruedUsd)
	}
	if bal.LockedUsdMicros > 0 {
		fmt.Printf("    Locked:    %.6f AKT (harvest pending)\n", float64(bal.LockedUsdMicros)/1e6/aktRate)
	}
	if bal.LifetimePaidUAKT > 0 {
		fmt.Printf("    Harvested: %.6f AKT\n", float64(bal.LifetimePaidUAKT)/1e6)
	}
	fmt.Println()

	// Wallet
	if cfg.WalletAddress != "" {
		fmt.Printf("  Wallet:     %s\n", cfg.WalletAddress)
	} else {
		fmt.Println("  Wallet:     not set")
		fmt.Println("              Set wallet_address in config.yaml to harvest rewards.")
	}
	fmt.Println()

	// Show recent withdrawals
	wResp, err := client.Get(coordinatorURL(cfg, "/internal/providers/"+cfg.ProviderID+"/withdrawals"))
	if err == nil {
		defer wResp.Body.Close()
		wBody, _ := io.ReadAll(wResp.Body)
		var wResult struct {
			Withdrawals []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
				NetUAkt int64 `json:"net_uakt"`
			} `json:"withdrawals"`
		}
		if json.Unmarshal(wBody, &wResult) == nil && len(wResult.Withdrawals) > 0 {
			fmt.Println("  Harvest History")
			for _, w := range wResult.Withdrawals {
				status := w.Status
				switch w.Status {
				case "locked":
					status = "queued"
				case "broadcast":
					status = "processing"
				case "confirmed":
					status = "harvested"
				case "failed":
					status = "failed (returned)"
				}
				fmt.Printf("    %s  %.6f AKT  %s\n", w.ID[:8], float64(w.NetUAkt)/1e6, status)
			}
			fmt.Println()
		}
	}

	return nil
}

func runHarvest(cmd *cobra.Command, args []string) error {
	cfg, err := loadPaymentConfig()
	if err != nil {
		return err
	}

	if cfg.WalletAddress == "" {
		fmt.Println()
		fmt.Println("  No wallet_address set in config.yaml.")
		fmt.Println("  Add your AKT address to start harvesting rewards:")
		fmt.Println()
		fmt.Println("    wallet_address: \"akash1...\"")
		fmt.Println()
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Sync wallet via heartbeat
	hbBody := fmt.Sprintf(`{"wallet_address":"%s"}`, cfg.WalletAddress)
	hbResp, err := client.Post(
		coordinatorURL(cfg, "/internal/providers/"+cfg.ProviderID+"/heartbeat"),
		"application/json", strings.NewReader(hbBody))
	if err != nil {
		return fmt.Errorf("could not reach coordinator: %w", err)
	}
	hbResp.Body.Close()

	// Request withdrawal
	resp, err := client.Post(
		coordinatorURL(cfg, "/internal/providers/"+cfg.ProviderID+"/withdraw"),
		"application/json", strings.NewReader("{}"))
	if err != nil {
		return fmt.Errorf("harvest request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// Parse error for friendly messages
		var errResp struct{ Error string `json:"error"` }
		if json.Unmarshal(body, &errResp) == nil {
			switch {
			case strings.Contains(errResp.Error, "no accrued balance"):
				fmt.Println()
				fmt.Println("  Nothing to harvest yet. Keep farming!")
				fmt.Println("  Rewards accrue daily based on stored data and score.")
				fmt.Println()
				return nil
			case strings.Contains(errResp.Error, "too small to cover gas"):
				fmt.Println()
				fmt.Println("  Accrued balance is too small to cover the AKT gas fee.")
				fmt.Println("  Keep farming -- rewards will grow with more data and time.")
				fmt.Println()
				return nil
			}
		}
		return fmt.Errorf("coordinator returned %d: %s", resp.StatusCode, body)
	}

	var w struct {
		ID           string  `json:"id"`
		Status       string  `json:"status"`
		NetUAkt      int64   `json:"net_uakt"`
		AktRateUsd   float64 `json:"akt_rate_usd"`
		NetUsdMicros int64   `json:"net_usd_micros"`
		WalletAddress string `json:"wallet_address"`
	}
	if err := json.Unmarshal(body, &w); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Println()
	fmt.Println("  Harvest submitted!")
	fmt.Println()
	fmt.Printf("    Amount: %.6f AKT ($%.6f USD)\n", float64(w.NetUAkt)/1e6, float64(w.NetUsdMicros)/1e6)
	fmt.Printf("    Rate:   $%.4f / AKT\n", w.AktRateUsd)
	fmt.Printf("    Wallet: %s\n", w.WalletAddress)
	fmt.Printf("    ID:     %s\n", w.ID)
	fmt.Println()
	fmt.Println("  Your harvest is queued for human-verified settlement.")
	fmt.Println("  AKT will be sent to your wallet within 24 hours.")
	fmt.Println()
	fmt.Println("  Run 'datafarmer info' to check status.")
	fmt.Println()

	return nil
}

func formatBytes(b int64) string {
	switch {
	case b >= 1_000_000_000:
		return fmt.Sprintf("%.2f GB", float64(b)/1e9)
	case b >= 1_000_000:
		return fmt.Sprintf("%.2f MB", float64(b)/1e6)
	case b >= 1_000:
		return fmt.Sprintf("%.2f KB", float64(b)/1e3)
	default:
		return fmt.Sprintf("%d bytes", b)
	}
}
