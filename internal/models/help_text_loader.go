package models

import (
	"bytes"
	"text/template"
)

// GenerateHelpTexts creates help texts with values from config
func GenerateHelpTexts(config map[string]interface{}) *OnboardingHelpTexts {
	// Start with default help texts
	helpTexts := DefaultOnboardingHelpTexts

	// Create template for each text that needs dynamic values
	didGenTemplate, _ := template.New("did").Parse(helpTexts.DIDGeneration.Command)
	fqdnTemplate, _ := template.New("fqdn").Parse(helpTexts.FQDNRequirements.Command)
	proofTemplate, _ := template.New("proof").Parse(helpTexts.DelegationProof.Command)

	// Execute templates with config values
	var didBuf, fqdnBuf, proofBuf bytes.Buffer
	if err := didGenTemplate.Execute(&didBuf, config); err == nil {
		helpTexts.DIDGeneration.Command = didBuf.String()
	}
	if err := fqdnTemplate.Execute(&fqdnBuf, config); err == nil {
		helpTexts.FQDNRequirements.Command = fqdnBuf.String()
	}
	if err := proofTemplate.Execute(&proofBuf, config); err == nil {
		helpTexts.DelegationProof.Command = proofBuf.String()
	}

	// Allow for dynamic description text too
	didDescTemplate, _ := template.New("didDesc").Parse(helpTexts.DIDGeneration.Description)
	fqdnDescTemplate, _ := template.New("fqdnDesc").Parse(helpTexts.FQDNRequirements.Description)
	proofDescTemplate, _ := template.New("proofDesc").Parse(helpTexts.DelegationProof.Description)

	var didDescBuf, fqdnDescBuf, proofDescBuf bytes.Buffer
	if err := didDescTemplate.Execute(&didDescBuf, config); err == nil {
		helpTexts.DIDGeneration.Description = didDescBuf.String()
	}
	if err := fqdnDescTemplate.Execute(&fqdnDescBuf, config); err == nil {
		helpTexts.FQDNRequirements.Description = fqdnDescBuf.String()
	}
	if err := proofDescTemplate.Execute(&proofDescBuf, config); err == nil {
		helpTexts.DelegationProof.Description = proofDescBuf.String()
	}

	return &helpTexts
}
