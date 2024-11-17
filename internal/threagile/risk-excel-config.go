package threagile

type RiskExcelConfig struct {
	HideColumns        []string           `json:"HideColumns,omitempty" yaml:"HideColumns"`
	SortByColumns      []string           `json:"SortByColumns,omitempty" yaml:"SortByColumns"`
	WidthOfColumns     map[string]float64 `json:"WidthOfColumns,omitempty" yaml:"WidthOfColumns"`
	ShrinkColumnsToFit bool               `json:"ShrinkColumnsToFit,omitempty" yaml:"ShrinkColumnsToFit"`
	WrapText           bool               `json:"WrapText,omitempty" yaml:"WrapText"`
	ColorText          bool               `json:"ColorText,omitempty" yaml:"ColorText"`
}
