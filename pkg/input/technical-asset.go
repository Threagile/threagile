package input

import "fmt"

type TechnicalAsset struct {
	ID                      string                       `yaml:"id" json:"id"`
	Description             string                       `yaml:"description" json:"description"`
	Type                    string                       `yaml:"type" json:"type"`
	Usage                   string                       `yaml:"usage" json:"usage"`
	UsedAsClientByHuman     bool                         `yaml:"used_as_client_by_human" json:"used_as_client_by_human"`
	OutOfScope              bool                         `yaml:"out_of_scope" json:"out_of_scope"`
	JustificationOutOfScope string                       `yaml:"justification_out_of_scope,omitempty" json:"justification_out_of_scope,omitempty"`
	Size                    string                       `yaml:"size" json:"size"`
	Technology              string                       `yaml:"technology,omitempty" json:"technology,omitempty"`
	Technologies            []string                     `yaml:"technologies,omitempty" json:"technologies,omitempty"`
	Tags                    []string                     `yaml:"tags,omitempty" json:"tags,omitempty"`
	Internet                bool                         `yaml:"internet" json:"internet"`
	Machine                 string                       `yaml:"machine" json:"machine"`
	Encryption              string                       `yaml:"encryption" json:"encryption"`
	Owner                   string                       `yaml:"owner" json:"owner"`
	Confidentiality         string                       `yaml:"confidentiality" json:"confidentiality"`
	Integrity               string                       `yaml:"integrity" json:"integrity"`
	Availability            string                       `yaml:"availability" json:"availability"`
	JustificationCiaRating  string                       `yaml:"justification_cia_rating,omitempty" json:"justification_cia_rating,omitempty"`
	MultiTenant             bool                         `yaml:"multi_tenant" json:"multi_tenant"`
	Redundant               bool                         `yaml:"redundant" json:"redundant"`
	CustomDevelopedParts    bool                         `yaml:"custom_developed_parts" json:"custom_developed_parts"`
	DataAssetsProcessed     []string                     `yaml:"data_assets_processed" json:"data_assets_processed"`
	DataAssetsStored        []string                     `yaml:"data_assets_stored" json:"data_assets_stored"`
	DataFormatsAccepted     []string                     `yaml:"data_formats_accepted" json:"data_formats_accepted"`
	DiagramTweakOrder       int                          `yaml:"diagram_tweak_order,omitempty" json:"diagram_tweak_order,omitempty"`
	CommunicationLinks      map[string]CommunicationLink `yaml:"communication_links" json:"communication_links"`
}

func (what *TechnicalAsset) Merge(other TechnicalAsset) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %w", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %w", mergeError)
	}

	what.Type, mergeError = new(Strings).MergeSingleton(what.Type, other.Type)
	if mergeError != nil {
		return fmt.Errorf("failed to merge type: %w", mergeError)
	}

	what.Usage, mergeError = new(Strings).MergeSingleton(what.Usage, other.Usage)
	if mergeError != nil {
		return fmt.Errorf("failed to merge usage: %w", mergeError)
	}

	if !what.UsedAsClientByHuman {
		what.UsedAsClientByHuman = other.UsedAsClientByHuman
	}

	if !what.OutOfScope {
		what.OutOfScope = other.OutOfScope
	}

	what.JustificationOutOfScope = new(Strings).MergeMultiline(what.JustificationOutOfScope, other.JustificationOutOfScope)

	what.Size, mergeError = new(Strings).MergeSingleton(what.Size, other.Size)
	if mergeError != nil {
		return fmt.Errorf("failed to merge size: %w", mergeError)
	}

	what.Technology, mergeError = new(Strings).MergeSingleton(what.Technology, other.Technology)
	if mergeError != nil {
		return fmt.Errorf("failed to merge technology: %w", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	if !what.Internet {
		what.Internet = other.Internet
	}

	what.Machine, mergeError = new(Strings).MergeSingleton(what.Machine, other.Machine)
	if mergeError != nil {
		return fmt.Errorf("failed to merge machine: %w", mergeError)
	}

	what.Encryption, mergeError = new(Strings).MergeSingleton(what.Encryption, other.Encryption)
	if mergeError != nil {
		return fmt.Errorf("failed to merge encryption: %w", mergeError)
	}

	what.Owner, mergeError = new(Strings).MergeSingleton(what.Owner, other.Owner)
	if mergeError != nil {
		return fmt.Errorf("failed to merge owner: %w", mergeError)
	}

	what.Confidentiality, mergeError = new(Strings).MergeSingleton(what.Confidentiality, other.Confidentiality)
	if mergeError != nil {
		return fmt.Errorf("failed to merge confidentiality: %w", mergeError)
	}

	what.Integrity, mergeError = new(Strings).MergeSingleton(what.Integrity, other.Integrity)
	if mergeError != nil {
		return fmt.Errorf("failed to merge integrity: %w", mergeError)
	}

	what.Availability, mergeError = new(Strings).MergeSingleton(what.Availability, other.Availability)
	if mergeError != nil {
		return fmt.Errorf("failed to merge availability: %w", mergeError)
	}

	what.JustificationCiaRating = new(Strings).MergeMultiline(what.JustificationCiaRating, other.JustificationCiaRating)

	if !what.MultiTenant {
		what.MultiTenant = other.MultiTenant
	}

	if !what.Redundant {
		what.Redundant = other.Redundant
	}

	if !what.CustomDevelopedParts {
		what.CustomDevelopedParts = other.CustomDevelopedParts
	}

	what.DataAssetsProcessed = new(Strings).MergeUniqueSlice(what.DataAssetsProcessed, other.DataAssetsProcessed)

	what.DataAssetsStored = new(Strings).MergeUniqueSlice(what.DataAssetsStored, other.DataAssetsStored)

	what.DataFormatsAccepted = new(Strings).MergeUniqueSlice(what.DataFormatsAccepted, other.DataFormatsAccepted)

	if what.DiagramTweakOrder == 0 {
		what.DiagramTweakOrder = other.DiagramTweakOrder
	}

	what.CommunicationLinks, mergeError = new(CommunicationLink).MergeMap(what.CommunicationLinks, other.CommunicationLinks)
	if mergeError != nil {
		return fmt.Errorf("failed to merge communication_links: %w", mergeError)
	}

	return nil
}

func (what *TechnicalAsset) MergeMap(first map[string]TechnicalAsset, second map[string]TechnicalAsset) (map[string]TechnicalAsset, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge technical asset %q: %w", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
