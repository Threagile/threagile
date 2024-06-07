/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

type TrustBoundary struct {
	Id                    string            `json:"id,omitempty" yaml:"id,omitempty"`
	Title                 string            `json:"title,omitempty" yaml:"title,omitempty"`
	Description           string            `json:"description,omitempty" yaml:"description,omitempty"`
	Type                  TrustBoundaryType `json:"type,omitempty" yaml:"type,omitempty"`
	Tags                  []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	TechnicalAssetsInside []string          `json:"technical_assets_inside,omitempty" yaml:"technical_assets_inside,omitempty"`
	TrustBoundariesNested []string          `json:"trust_boundaries_nested,omitempty" yaml:"trust_boundaries_nested,omitempty"`
}

func (what TrustBoundary) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}
