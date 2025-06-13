package input

type Overview struct {
	SourceFile  string              `yaml:"source-file,omitempty" json:"source-file,omitempty"`
	Description string              `yaml:"description,omitempty" json:"description,omitempty"`
	Images      []map[string]string `yaml:"images,omitempty" json:"images,omitempty"` // yes, array of map here, as array keeps the order of the image keys
}

func (what *Overview) Merge(other Overview) error {
	if len(what.Description) > 0 {
		if len(other.Description) > 0 {
			what.Description += lineSeparator + other.Description
		}
	} else {
		what.Description = other.Description
	}

	what.Images = append(what.Images, other.Images...)

	return nil
}
