/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

type CommunicationLink struct {
	Id                     string         `json:"id,omitempty" yaml:"id,omitempty"`
	SourceId               string         `json:"source_id,omitempty" yaml:"source_id,omitempty"`
	TargetId               string         `json:"target_id,omitempty" yaml:"target_id,omitempty"`
	Title                  string         `json:"title,omitempty" yaml:"title,omitempty"`
	Description            string         `json:"description,omitempty" yaml:"description,omitempty"`
	Protocol               Protocol       `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Tags                   []string       `json:"tags,omitempty" yaml:"tags,omitempty"`
	VPN                    bool           `json:"vpn,omitempty" yaml:"vpn,omitempty"`
	IpFiltered             bool           `json:"ip_filtered,omitempty" yaml:"ip_filtered,omitempty"`
	Readonly               bool           `json:"readonly,omitempty" yaml:"readonly,omitempty"`
	Authentication         Authentication `json:"authentication,omitempty" yaml:"authentication,omitempty"`
	Authorization          Authorization  `json:"authorization,omitempty" yaml:"authorization,omitempty"`
	Usage                  Usage          `json:"usage,omitempty" yaml:"usage,omitempty"`
	DataAssetsSent         []string       `json:"data_assets_sent,omitempty" yaml:"data_assets_sent,omitempty"`
	DataAssetsReceived     []string       `json:"data_assets_received,omitempty" yaml:"data_assets_received,omitempty"`
	DiagramTweakWeight     int            `json:"diagram_tweak_weight,omitempty" yaml:"diagram_tweak_weight,omitempty"`
	DiagramTweakConstraint bool           `json:"diagram_tweak_constraint,omitempty" yaml:"diagram_tweak_constraint,omitempty"`
}

func (what CommunicationLink) IsTaggedWithAny(tags ...string) bool {
	return containsCaseInsensitiveAny(what.Tags, tags...)
}

func (what CommunicationLink) IsBidirectional() bool {
	return len(what.DataAssetsSent) > 0 && len(what.DataAssetsReceived) > 0
}

type ByTechnicalCommunicationLinkIdSort []*CommunicationLink

func (what ByTechnicalCommunicationLinkIdSort) Len() int      { return len(what) }
func (what ByTechnicalCommunicationLinkIdSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalCommunicationLinkIdSort) Less(i, j int) bool {
	return what[i].Id > what[j].Id
}

type ByTechnicalCommunicationLinkTitleSort []*CommunicationLink

func (what ByTechnicalCommunicationLinkTitleSort) Len() int      { return len(what) }
func (what ByTechnicalCommunicationLinkTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what ByTechnicalCommunicationLinkTitleSort) Less(i, j int) bool {
	return what[i].Title > what[j].Title
}
