package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/storacha/delegator/pkg/client"
)

// onboardCmd represents the onboard command
var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "WSP onboarding commands",
	Long:  `Commands for Warm Storage Provider onboarding process.`,
}

// registerDIDCmd represents the register-did command
var registerDIDCmd = &cobra.Command{
	Use:   "register-did",
	Short: "Register DID and generate delegation",
	Long: `Step 3.1: Verify WSP DID is in allowlist and generate delegation for indexer access.

This command will:
1. Check if your DID is in the allowlist
2. Verify the DID is not already registered
3. Generate a delegation for accessing the indexer
4. Provide download instructions`,
	RunE: runVerifyDID,
}

// registerFQDNCmd represents the register-fqdn command
var registerFQDNCmd = &cobra.Command{
	Use:   "register-fqdn",
	Short: "Register and verify FQDN",
	Long: `Step 3.3: Verify WSP FQDN returns the correct DID and perform readiness check.

This command will:
1. Verify your FQDN is accessible and returns the correct DID
2. Update your onboarding session status
3. Provide instructions for generating upload delegation`,
	RunE: runRegisterFQDN,
}

// registerProofCmd represents the register-proof command
var registerProofCmd = &cobra.Command{
	Use:   "register-proof",
	Short: "Register and verify proof delegation",
	Long: `Step 3.4: Submit proof delegation and complete WSP onboarding.

This command will:
1. Verify the provided proof delegation is valid
2. Register your WSP in the provider registry
3. Complete the onboarding process`,
	RunE: runRegisterProof,
}

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check onboarding session status",
	Long:  `Check the status of an ongoing onboarding session.`,
	RunE:  runStatus,
}

// downloadDelegationCmd represents the download-delegation command
var downloadDelegationCmd = &cobra.Command{
	Use:   "download-delegation",
	Short: "Download delegation file",
	Long:  `Download the delegation file for your onboarding session.`,
	RunE:  runDownloadDelegation,
}

var (
	didFlag       string
	sessionIDFlag string
	outputFile    string
	urlFlag       string
	proofFlag     string
)

func init() {
	clientCmd.AddCommand(onboardCmd)
	onboardCmd.AddCommand(registerDIDCmd)
	onboardCmd.AddCommand(registerFQDNCmd)
	onboardCmd.AddCommand(registerProofCmd)
	onboardCmd.AddCommand(statusCmd)
	onboardCmd.AddCommand(downloadDelegationCmd)

	// register-did flags
	registerDIDCmd.Flags().StringVar(&didFlag, "did", "", "WSP DID (required)")
	registerDIDCmd.MarkFlagRequired("did")

	// register-fqdn flags
	registerFQDNCmd.Flags().StringVar(&sessionIDFlag, "session-id", "", "Onboarding session ID (required)")
	registerFQDNCmd.Flags().StringVar(&urlFlag, "url", "", "WSP FQDN URL (required)")
	registerFQDNCmd.MarkFlagRequired("session-id")
	registerFQDNCmd.MarkFlagRequired("url")

	// register-proof flags
	registerProofCmd.Flags().StringVar(&sessionIDFlag, "session-id", "", "Onboarding session ID (required)")
	registerProofCmd.Flags().StringVar(&proofFlag, "proof", "", "Upload delegation proof (required)")
	registerProofCmd.MarkFlagRequired("session-id")
	registerProofCmd.MarkFlagRequired("proof")

	// status flags
	statusCmd.Flags().StringVar(&sessionIDFlag, "session-id", "", "Onboarding session ID (required)")
	statusCmd.MarkFlagRequired("session-id")

	// download-delegation flags
	downloadDelegationCmd.Flags().StringVar(&sessionIDFlag, "session-id", "", "Onboarding session ID (required)")
	downloadDelegationCmd.Flags().StringVar(&outputFile, "output", "delegation.b64", "Output file path")
	downloadDelegationCmd.MarkFlagRequired("session-id")
}

func runVerifyDID(cmd *cobra.Command, args []string) error {
	c, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	resp, err := c.RegisterDID(newContext(), didFlag)
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok {
			if apiErr.IsForbidden() {
				return fmt.Errorf("DID not allowed: %w", err)
			}
			if apiErr.IsConflict() {
				return fmt.Errorf("DID already registered: %w", err)
			}
		}
		return fmt.Errorf("registering DID: %w", err)
	}

	// Pretty print the response
	output, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("formatting response: %w", err)
	}

	fmt.Println(string(output))

	// Provide next steps
	fmt.Printf("\n\nNext steps:\n")
	fmt.Printf("1. Download your delegation file:\n")
	fmt.Printf("   delegator client onboard download-delegation --session-id %s\n\n", resp.SessionID)
	fmt.Printf("2. Configure and start your Piri node with the delegation\n\n")
	fmt.Printf("3. Register your FQDN:\n")
	fmt.Printf("   delegator client onboard register-fqdn --session-id %s --url https://your-fqdn.com\n\n", resp.SessionID)
	fmt.Printf("4. Check your session status:\n")
	fmt.Printf("   delegator client onboard status --session-id %s\n\n", resp.SessionID)

	return nil
}

func runRegisterFQDN(cmd *cobra.Command, args []string) error {
	c, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	resp, err := c.RegisterFQDN(newContext(), sessionIDFlag, urlFlag)
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok {
			if apiErr.IsNotFound() {
				return fmt.Errorf("session not found: %w", err)
			}
			if apiErr.IsBadRequest() {
				return fmt.Errorf("invalid FQDN or session state: %w", err)
			}
		}
		return fmt.Errorf("registering FQDN: %w", err)
	}

	// Pretty print the response
	output, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("formatting response: %w", err)
	}

	fmt.Println(string(output))

	// Provide next steps
	fmt.Printf("\n\nNext steps:\n")
	fmt.Printf("1. Generate a delegation on your storage node for the upload service\n")
	fmt.Printf("2. Submit the delegation/proof to complete onboarding:\n")
	fmt.Printf("   delegator client onboard register-proof --session-id %s --proof \"<your-delegation-proof>\"\n", sessionIDFlag)
	fmt.Printf("3. Check your session status:\n")
	fmt.Printf("   delegator client onboard status --session-id %s\n\n", sessionIDFlag)

	return nil
}

func runRegisterProof(cmd *cobra.Command, args []string) error {
	c, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	resp, err := c.RegisterProof(newContext(), sessionIDFlag, proofFlag)
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok {
			if apiErr.IsNotFound() {
				return fmt.Errorf("session not found: %w", err)
			}
			if apiErr.IsBadRequest() {
				return fmt.Errorf("invalid proof or session state: %w", err)
			}
		}
		return fmt.Errorf("registering proof: %w", err)
	}

	// Pretty print the response
	output, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("formatting response: %w", err)
	}

	fmt.Println(string(output))

	// Provide completion message
	fmt.Printf("\n\nCongratulations! Your WSP onboarding is complete.\n")
	fmt.Printf("Your storage provider has been registered and you can now receive deals.\n\n")
	fmt.Printf("To check your final status:\n")
	fmt.Printf("   delegator client onboard status --session-id %s\n\n", sessionIDFlag)

	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	c, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	resp, err := c.GetStatus(newContext(), sessionIDFlag)
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok {
			if apiErr.IsNotFound() {
				return fmt.Errorf("session not found: %w", err)
			}
		}
		return fmt.Errorf("getting session status: %w", err)
	}

	output, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("formatting response: %w", err)
	}

	cmd.Println(string(output))
	return nil
}

func runDownloadDelegation(cmd *cobra.Command, args []string) error {
	c, err := newClient()
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	data, err := c.DownloadDelegation(newContext(), sessionIDFlag)
	if err != nil {
		if apiErr, ok := err.(*client.APIError); ok {
			if apiErr.IsNotFound() {
				return fmt.Errorf("delegation not found: %w", err)
			}
		}
		return fmt.Errorf("downloading delegation: %w", err)
	}

	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputFile)
	if outputDir != "." {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	// Write delegation data to file
	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("writing delegation file: %w", err)
	}

	cmd.Printf("Delegation downloaded successfully to: %s\n", outputFile)
	cmd.Println("\nNext steps:")
	cmd.Println("1. Configure your Piri node with this delegation file")
	cmd.Println("2. Start your Piri node and verify it's accessible")
	cmd.Println("3. Proceed to FQDN verification (Step 3.2)")

	return nil
}
