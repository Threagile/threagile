package input

import (
	"errors"
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

func (what *CommunicationLink) Merge(config configReader, other CommunicationLink) (bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	what.ID, isFatal, mergeError = new(Strings).MergeSingleton(config, what.ID, other.ID)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge id: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge id: %w", mergeError), mergeErrors)
	}

	what.Source, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Source, other.Source)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge source: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge source: %w", mergeError), mergeErrors)
	}

	what.Target, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Target, other.Target)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge target: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge target: %w", mergeError), mergeErrors)
	}

	what.Description, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Description, other.Description)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge description: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge description: %w", mergeError), mergeErrors)
	}

	what.Protocol, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Protocol, other.Protocol)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge protocol: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge protocol: %w", mergeError), mergeErrors)
	}

	what.Authentication, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Authentication, other.Authentication)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge authentication: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge authentication: %w", mergeError), mergeErrors)
	}

	what.Authorization, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Authorization, other.Authorization)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge authorization: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge authorization: %w", mergeError), mergeErrors)
	}

	what.Tags = new(Strings).MergeUniqueSlice(config, what.Tags, other.Tags)

	if !what.VPN {
		what.VPN = other.VPN
	}

	if !what.IpFiltered {
		what.IpFiltered = other.IpFiltered
	}

	if !what.Readonly {
		what.Readonly = other.Readonly
	}

	what.Usage, isFatal, mergeError = new(Strings).MergeSingleton(config, what.Usage, other.Usage)
	if mergeError != nil {
		if !config.GetMergeModels() || isFatal {
			return isFatal, fmt.Errorf("failed to merge usage: %w", mergeError)
		}

		mergeErrors = errors.Join(fmt.Errorf("failed to merge usage: %w", mergeError), mergeErrors)
	}

	what.DataAssetsSent = new(Strings).MergeUniqueSlice(config, what.DataAssetsSent, other.DataAssetsSent)

	what.DataAssetsReceived = new(Strings).MergeUniqueSlice(config, what.DataAssetsReceived, other.DataAssetsReceived)

	if what.DiagramTweakWeight == 0 {
		what.DiagramTweakWeight = other.DiagramTweakWeight
	}

	if !what.DiagramTweakConstraint {
		what.DiagramTweakConstraint = other.DiagramTweakConstraint
	}

	return isFatal, mergeErrors
}

func (what *CommunicationLink) MergeMap(config configReader, first map[string]CommunicationLink, second map[string]CommunicationLink) (map[string]CommunicationLink, bool, error) {
	var mergeErrors error
	var mergeError error
	var isFatal bool
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			isFatal, mergeError = mapItem.Merge(config, mapValue)
			if mergeError != nil {
				if !config.GetMergeModels() || isFatal {
					return first, isFatal, fmt.Errorf("failed to merge communication link %q: %w", mapKey, mergeError)
				}

				mergeErrors = errors.Join(fmt.Errorf("failed to merge communication link %q: %w", mapKey, mergeError), mergeErrors)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, isFatal, mergeErrors
}
