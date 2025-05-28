package models

// HelpText contains help text sections for onboarding pages
type HelpText struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Command     string `yaml:"command"`
}

// OnboardingHelpTexts contains help text for different onboarding sections
type OnboardingHelpTexts struct {
	DIDGeneration    HelpText `yaml:"did_generation"`
	FQDNRequirements HelpText `yaml:"fqdn_requirements"`
	DelegationProof  HelpText `yaml:"delegation_proof"`
}

// DefaultOnboardingHelpTexts provides the default help text for onboarding
var DefaultOnboardingHelpTexts = OnboardingHelpTexts{
	DIDGeneration: HelpText{
		Title:       "How do I get my storage nodes DID?",
		Description: "You should have already generated your DID and secret key using the 'storage id gen' command when setting up your node. You were instructed to save this output to a file. The DID is in that file and should be entered here.",
		Command:     "# If you saved to a PEM file:\nstorage id parse service.pem\n\n# If you saved to a JSON file, find the \"did\" field in the JSON\n# Example output:\n# {\n#   \"did\": \"did:key:z6Mkj...\",\n#   ...\n# }",
	},
	FQDNRequirements: HelpText{
		Title:       "Requirements",
		Description: "Your storage node must meet these requirements to pass verification{{if .ServiceName}} for {{.ServiceName}}{{end}}:",
		Command:     "# Your storage node must be configured to respond with your DID\n# Make sure your node is running and accessible via the URL you provide",
	},
	DelegationProof: HelpText{
		Title:       "How to generate",
		Description: "Generate a delegation proof using the storage CLI and your DID's private key file that you saved during setup{{if .ServiceDid}} (use the indexer DID: {{.ServiceDid}}){{end}}:",
		Command:     "# Using the key file you saved during setup (either PEM or JSON format):\nstorage delegation generate \\\n  --key-file=service.pem \\\n  --client-did={{.ServiceDid}}\n\n# If you saved your key as JSON instead of PEM:\nstorage delegation generate \\\n  --key-file=service.json \\\n  --client-did={{if .ServiceDid}}{{.ServiceDid}}{{else}}<indexer-did>{{end}}",
	},
}
