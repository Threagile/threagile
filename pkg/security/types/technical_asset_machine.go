/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

type TechnicalAssetMachine int

const (
	Physical TechnicalAssetMachine = iota
	Virtual
	Container
	Serverless
)

func TechnicalAssetMachineValues() []TypeEnum {
	return []TypeEnum{
		Physical,
		Virtual,
		Container,
		Serverless,
	}
}

var TechnicalAssetMachineTypeDescription = [...]TypeDescription{
	{"physical", "A physical machine"},
	{"virtual", "A virtual machine"},
	{"container", "A container"},
	{"serverless", "A serverless application"},
}

func (what TechnicalAssetMachine) String() string {
	return TechnicalAssetMachineTypeDescription[what].Name
}

func (what TechnicalAssetMachine) Explain() string {
	return TechnicalAssetMachineTypeDescription[what].Description
}
