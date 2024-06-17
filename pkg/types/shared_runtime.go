/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

type SharedRuntime struct {
	Id                     string   `json:"id,omitempty" yaml:"id,omitempty"`
	Title                  string   `json:"title,omitempty" yaml:"title,omitempty"`
	Description            string   `json:"description,omitempty" yaml:"description,omitempty"`
	Tags                   []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	TechnicalAssetsRunning []string `json:"technical_assets_running,omitempty" yaml:"technical_assets_running,omitempty"`
}

func (what SharedRuntime) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}
