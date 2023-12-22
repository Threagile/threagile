/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

type DataFormat int

const (
	JSON DataFormat = iota
	XML
	Serialization
	File
	CSV
)

func DataFormatValues() []TypeEnum {
	return []TypeEnum{
		JSON,
		XML,
		Serialization,
		File,
		CSV,
	}
}

var DataFormatTypeDescription = [...]TypeDescription{
	{"json", "JSON"},
	{"xml", "XML"},
	{"serialization", "Serialized program objects"},
	{"file", "Specific file types for data"},
	{"csv", "CSV"},
}

func (what DataFormat) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return DataFormatTypeDescription[what].Name
}

func (what DataFormat) Explain() string {
	return DataFormatTypeDescription[what].Description
}

func (what DataFormat) Title() string {
	return [...]string{"JSON", "XML", "Serialization", "File", "CSV"}[what]
}

func (what DataFormat) Description() string {
	return [...]string{"JSON marshalled object data", "XML structured data", "Serialization-based object graphs",
		"File input/uploads", "CSV tabular data"}[what]
}

type ByDataFormatAcceptedSort []DataFormat

func (what ByDataFormatAcceptedSort) Len() int      { return len(what) }
func (what ByDataFormatAcceptedSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataFormatAcceptedSort) Less(i, j int) bool {
	return what[i].String() < what[j].String()
}
