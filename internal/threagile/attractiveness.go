package threagile

type Attractiveness struct {
	Quantity        int           `json:"quantity,omitempty" yaml:"quantity"`
	Confidentiality AttackerFocus `json:"confidentiality" yaml:"confidentiality"`
	Integrity       AttackerFocus `json:"integrity" yaml:"integrity"`
	Availability    AttackerFocus `json:"availability" yaml:"availability"`
}
