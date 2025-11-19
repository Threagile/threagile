/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

type DataAsset struct {
	Id                     string          `yaml:"id,omitempty" json:"id,omitempty"`                   // TODO: tag here still required?
	Title                  string          `yaml:"title,omitempty" json:"title,omitempty"`             // TODO: tag here still required?
	Description            string          `yaml:"description,omitempty" json:"description,omitempty"` // TODO: tag here still required?
	Usage                  Usage           `yaml:"usage,omitempty" json:"usage,omitempty"`
	Tags                   []string        `yaml:"tags,omitempty" json:"tags,omitempty"`
	Origin                 string          `yaml:"origin,omitempty" json:"origin,omitempty"`
	Owner                  string          `yaml:"owner,omitempty" json:"owner,omitempty"`
	Quantity               Quantity        `yaml:"quantity,omitempty" json:"quantity,omitempty"`
	Confidentiality        Confidentiality `yaml:"confidentiality,omitempty" json:"confidentiality,omitempty"`
	Integrity              Criticality     `yaml:"integrity,omitempty" json:"integrity,omitempty"`
	Availability           Criticality     `yaml:"availability,omitempty" json:"availability,omitempty"`
	JustificationCiaRating string          `yaml:"justification_cia_rating,omitempty" json:"justification_cia_rating,omitempty"`
	PINameType             PINameType      `yaml:"pinametype,omitempty" json:"pinametype,omitempty"`
}

func (what DataAsset) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

type ByDataAssetTitleSort []*DataAsset

func (what ByDataAssetTitleSort) Len() int      { return len(what) }
func (what ByDataAssetTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByDataAssetTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}
