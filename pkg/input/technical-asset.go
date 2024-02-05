package input

import "fmt"

type TechnicalAsset struct {
	ID                      string                       `yaml:"id,omitempty" json:"id,omitempty"`
	Description             string                       `yaml:"description,omitempty" json:"description,omitempty"`
	Type                    string                       `yaml:"type,omitempty" json:"type,omitempty"`
	Usage                   string                       `yaml:"usage,omitempty" json:"usage,omitempty"`
	UsedAsClientByHuman     bool                         `yaml:"used_as_client_by_human,omitempty" json:"used_as_client_by_human,omitempty"`
	OutOfScope              bool                         `yaml:"out_of_scope,omitempty" json:"out_of_scope,omitempty"`
	JustificationOutOfScope string                       `yaml:"justification_out_of_scope,omitempty" json:"justification_out_of_scope,omitempty"`
	Size                    string                       `yaml:"size,omitempty" json:"size,omitempty"`
	Technology              string                       `yaml:"technology,omitempty" json:"technology,omitempty"`
	Tags                    []string                     `yaml:"tags,omitempty" json:"tags,omitempty"`
	Internet                bool                         `yaml:"internet,omitempty" json:"internet,omitempty"`
	Machine                 string                       `yaml:"machine,omitempty" json:"machine,omitempty"`
	Encryption              string                       `yaml:"encryption,omitempty" json:"encryption,omitempty"`
	Owner                   string                       `yaml:"owner,omitempty" json:"owner,omitempty"`
	Confidentiality         string                       `yaml:"confidentiality,omitempty" json:"confidentiality,omitempty"`
	Integrity               string                       `yaml:"integrity,omitempty" json:"integrity,omitempty"`
	Availability            string                       `yaml:"availability,omitempty" json:"availability,omitempty"`
	JustificationCiaRating  string                       `yaml:"justification_cia_rating,omitempty" json:"justification_cia_rating,omitempty"`
	MultiTenant             bool                         `yaml:"multi_tenant,omitempty" json:"multi_tenant,omitempty"`
	Redundant               bool                         `yaml:"redundant,omitempty" json:"redundant,omitempty"`
	CustomDevelopedParts    bool                         `yaml:"custom_developed_parts,omitempty" json:"custom_developed_parts,omitempty"`
	DataAssetsProcessed     []string                     `yaml:"data_assets_processed,omitempty" json:"data_assets_processed,omitempty"`
	DataAssetsStored        []string                     `yaml:"data_assets_stored,omitempty" json:"data_assets_stored,omitempty"`
	DataFormatsAccepted     []string                     `yaml:"data_formats_accepted,omitempty" json:"data_formats_accepted,omitempty"`
	DiagramTweakOrder       int                          `yaml:"diagram_tweak_order,omitempty" json:"diagram_tweak_order,omitempty"`
	CommunicationLinks      map[string]CommunicationLink `yaml:"communication_links,omitempty" json:"communication_links,omitempty"`
}

func (what *TechnicalAsset) Merge(other TechnicalAsset) error {
	var mergeError error
	what.ID, mergeError = new(Strings).MergeSingleton(what.ID, other.ID)
	if mergeError != nil {
		return fmt.Errorf("failed to merge id: %v", mergeError)
	}

	what.Description, mergeError = new(Strings).MergeSingleton(what.Description, other.Description)
	if mergeError != nil {
		return fmt.Errorf("failed to merge description: %v", mergeError)
	}

	what.Type, mergeError = new(Strings).MergeSingleton(what.Type, other.Type)
	if mergeError != nil {
		return fmt.Errorf("failed to merge type: %v", mergeError)
	}

	what.Usage, mergeError = new(Strings).MergeSingleton(what.Usage, other.Usage)
	if mergeError != nil {
		return fmt.Errorf("failed to merge usage: %v", mergeError)
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
		return fmt.Errorf("failed to merge size: %v", mergeError)
	}

	what.Technology, mergeError = new(Strings).MergeSingleton(what.Technology, other.Technology)
	if mergeError != nil {
		return fmt.Errorf("failed to merge technology: %v", mergeError)
	}

	what.Tags = new(Strings).MergeUniqueSlice(what.Tags, other.Tags)

	if !what.Internet {
		what.Internet = other.Internet
	}

	what.Machine, mergeError = new(Strings).MergeSingleton(what.Machine, other.Machine)
	if mergeError != nil {
		return fmt.Errorf("failed to merge machine: %v", mergeError)
	}

	what.Encryption, mergeError = new(Strings).MergeSingleton(what.Encryption, other.Encryption)
	if mergeError != nil {
		return fmt.Errorf("failed to merge encryption: %v", mergeError)
	}

	what.Owner, mergeError = new(Strings).MergeSingleton(what.Owner, other.Owner)
	if mergeError != nil {
		return fmt.Errorf("failed to merge owner: %v", mergeError)
	}

	what.Confidentiality, mergeError = new(Strings).MergeSingleton(what.Confidentiality, other.Confidentiality)
	if mergeError != nil {
		return fmt.Errorf("failed to merge confidentiality: %v", mergeError)
	}

	what.Integrity, mergeError = new(Strings).MergeSingleton(what.Integrity, other.Integrity)
	if mergeError != nil {
		return fmt.Errorf("failed to merge integrity: %v", mergeError)
	}

	what.Availability, mergeError = new(Strings).MergeSingleton(what.Availability, other.Availability)
	if mergeError != nil {
		return fmt.Errorf("failed to merge availability: %v", mergeError)
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
		return fmt.Errorf("failed to merge communication_links: %v", mergeError)
	}

	return nil
}

func (what *TechnicalAsset) MergeMap(first map[string]TechnicalAsset, second map[string]TechnicalAsset) (map[string]TechnicalAsset, error) {
	for mapKey, mapValue := range second {
		mapItem, ok := first[mapKey]
		if ok {
			mergeError := mapItem.Merge(mapValue)
			if mergeError != nil {
				return first, fmt.Errorf("failed to merge technical asset %q: %v", mapKey, mergeError)
			}

			first[mapKey] = mapItem
		} else {
			first[mapKey] = mapValue
		}
	}

	return first, nil
}
