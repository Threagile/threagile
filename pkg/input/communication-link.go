package input

import (
	"fmt"
)

type CommunicationLink struct {
	SourceFile             string   `yaml:"-" json:"-"`
	ID                     string   `yaml:"id,omitempty" json:"id,omitempty"`
	Source                 string   `yaml:"source,omitempty" json:"source,omitempty"`
	Target                 string   `yaml:"target,omitempty" json:"target,omitempty"`
	Description            string   `yaml:"description,omitempty" json:"description,omitempty"`
	Protocol               string   `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Authentication         string   `yaml:"authentication,omitempty" json:"authentication,omitempty"`
	Authorization          string   `yaml:"authorization,omitempty" json:"authorization,omitempty"`
	Tags                   []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	VPN                    bool     `yaml:"vpn,omitempty" json:"vpn,omitempty"`
	IpFiltered             bool     `yaml:"ip_filtered,omitempty" json:"ip_filtered,omitempty"`
	Readonly               bool     `yaml:"readonly,omitempty" json:"readonly,omitempty"`
	Usage                  string   `yaml:"usage,omitempty" json:"usage,omitempty"`
	DataAssetsSent         []string `yaml:"data_assets_sent,omitempty" json:"data_assets_sent,omitempty"`
	DataAssetsReceived     []string `yaml:"data_assets_received,omitempty" json:"data_assets_received,omitempty"`
	DiagramTweakWeight     int      `yaml:"diagram_tweak_weight,omitempty" json:"diagram_tweak_weight,omitempty"`
	DiagramTweakConstraint bool     `yaml:"diagram_tweak_constraint,omitempty" json:"diagram_tweak_constraint,omitempty"`
	IsTemplate             bool     `yaml:"is_template,omitempty" json:"is_template,omitempty"`
}

func (what *CommunicationLink) Merge(other CommunicationLink) error {
	var mergeError error
	what.Target, mergeError = new(Strings).MergeSingleton(what.Target, other.Target)
	if mergeError != nil {
		return fmt.Errorf("failed to merge target: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Protocol, mergeError = new(Strings).MergeSingleton(what.Protocol, other.Protocol)
	if mergeError != nil {
		return fmt.Errorf("failed to merge protocol: %w", mergeError)
	}

	what.Authentication, mergeError = new(Strings).MergeSingleton(what.Authentication, other.Authentication)
	if mergeError != nil {
		return fmt.Errorf("failed to merge authentication: %w", mergeError)
	}

	what.Authorization, mergeError = new(Strings).MergeSingleton(what.Authorization, other.Authorization)
	if mergeError != nil {
		return fmt.Errorf("failed to merge authorization: %w", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	if !what.VPN {
		what.VPN = other.VPN
	}

	if !what.IpFiltered {
		what.IpFiltered = other.IpFiltered
	}

	if !what.Readonly {
		what.Readonly = other.Readonly
	}

	what.Usage, mergeError = new(Strings).MergeSingleton(what.Usage, other.Usage)
	if mergeError != nil {
		return fmt.Errorf("failed to merge usage: %w", mergeError)
	}

	what.DataAssetsSent = new(Strings).MergeUniqueSlice(what.DataAssetsSent, other.DataAssetsSent)

	what.DataAssetsReceived = new(Strings).MergeUniqueSlice(what.DataAssetsReceived, other.DataAssetsReceived)

	if what.DiagramTweakWeight == 0 {
		what.DiagramTweakWeight = other.DiagramTweakWeight
	}

	if !what.DiagramTweakConstraint {
		what.DiagramTweakConstraint = other.DiagramTweakConstraint
	}

	return nil
}

func (what *CommunicationLink) MergeMap(config configReader, first map[string]CommunicationLink, second map[string]CommunicationLink) (map[string]CommunicationLink, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			config.GetProgressReporter().Warnf("communication link %q from %q redefined in %q", mapKey, mapValue.SourceFile, mapItem.SourceFile)

			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge communication link %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
