/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

// TypeDescription contains a name for a type and its description
type TypeDescription struct {
	Name        string
	Description string
}

type TypeEnum interface {
	String() string
	Explain() string
}

func GetBuiltinTypeValues() map[string][]TypeEnum {
	return map[string][]TypeEnum{
		"Authentication":  AuthenticationValues(),
		"Authorization":   AuthorizationValues(),
		"Confidentiality": ConfidentialityValues(),
		"Criticality (for integrity and availability)": CriticalityValues(),
		"Data Breach Probability":                      DataBreachProbabilityValues(),
		"Data Format":                                  DataFormatValues(),
		"Encryption":                                   EncryptionStyleValues(),
		"Protocol":                                     ProtocolValues(),
		"Quantity":                                     QuantityValues(),
		"Risk Exploitation Impact":                     RiskExploitationImpactValues(),
		"Risk Exploitation Likelihood":                 RiskExploitationLikelihoodValues(),
		"Risk Function":                                RiskFunctionValues(),
		"Risk Severity":                                RiskSeverityValues(),
		"Risk Status":                                  RiskStatusValues(),
		"STRIDE":                                       STRIDEValues(),
		"Technical Asset Machine":                      TechnicalAssetMachineValues(),
		"Technical Asset Size":                         TechnicalAssetSizeValues(),
		"Technical Asset Technology":                   TechnicalAssetTechnologyValues(),
		"Technical Asset Type":                         TechnicalAssetTypeValues(),
		"Trust Boundary Type":                          TrustBoundaryTypeValues(),
		"Usage":                                        UsageValues(),
	}
}
