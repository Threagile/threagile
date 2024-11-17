package types

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed technologies.yaml
var technologiesLocation embed.FS

type TechnologyMap map[string]Technology

type technologyMapConfigReader interface {
	GetAppFolder() string
	GetTechnologyFilename() string
}

func (what TechnologyMap) LoadWithConfig(config technologyMapConfigReader, defaultFilename string) error {
	technologiesFilename := filepath.Join(config.GetAppFolder(), defaultFilename)
	_, statError := os.Stat(technologiesFilename)
	if statError == nil {
		technologiesLoadError := what.LoadFromFile(technologiesFilename)
		if technologiesLoadError != nil {
			return fmt.Errorf("error loading technologies: %w", technologiesLoadError)
		}
	} else {
		technologiesLoadError := what.LoadDefault()
		if technologiesLoadError != nil {
			return fmt.Errorf("error loading technologies: %w", technologiesLoadError)
		}
	}

	if len(config.GetTechnologyFilename()) > 0 {
		additionalTechnologies := make(TechnologyMap)
		loadError := additionalTechnologies.LoadFromFile(config.GetTechnologyFilename())
		if loadError != nil {
			return fmt.Errorf("error loading additional technologies from %q: %v", config.GetTechnologyFilename(), loadError)
		}

		for name, technology := range additionalTechnologies {
			what[name] = technology
		}
	}

	return nil
}

func (what TechnologyMap) LoadDefault() error {
	defaultTechnologyFile, readError := technologiesLocation.ReadFile("technologies.yaml")
	if readError != nil {
		return fmt.Errorf("error reading default technologies: %w", readError)
	}

	unmarshalError := yaml.Unmarshal(defaultTechnologyFile, &what)
	if unmarshalError != nil {
		return fmt.Errorf("error parsing default technologies: %w", unmarshalError)
	}

	return nil
}

func (what TechnologyMap) LoadFromFile(filename string) error {
	// #nosec G304 // fine for potential file for now because used mostly internally or as part of CI/CD
	data, readError := os.ReadFile(filename)
	if readError != nil {
		return fmt.Errorf("error reading technologies from %q: %w", filename, readError)
	}

	unmarshalError := yaml.Unmarshal(data, &what)
	if unmarshalError != nil {
		return fmt.Errorf("error parsing technologies from %q: %w", filename, unmarshalError)
	}

	return nil
}

func (what TechnologyMap) Save(filename string) error {
	data, marshalError := yaml.Marshal(what)
	if marshalError != nil {
		return fmt.Errorf("error marshalling technologies: %w", marshalError)
	}

	writeError := os.WriteFile(filename, data, 0600)
	if writeError != nil {
		return fmt.Errorf("error writing %q: %w", filename, writeError)
	}

	return nil
}

func (what TechnologyMap) Copy(from Technology) error {
	data, marshalError := yaml.Marshal(from)
	if marshalError != nil {
		return fmt.Errorf("error marshalling technologies: %w", marshalError)
	}

	unmarshalError := yaml.Unmarshal(data, &what)
	if unmarshalError != nil {
		return fmt.Errorf("error parsing technologies: %w", unmarshalError)
	}

	return nil
}

func (what TechnologyMap) Get(name string) *Technology {
	technology, exists := what[name]
	if !exists {
		return nil
	}

	return &technology
}

func (what TechnologyMap) GetAll(names ...string) ([]*Technology, error) {
	technologies := make([]*Technology, 0)
	for _, name := range names {
		technicalAssetTechnology := what.Get(name)
		if technicalAssetTechnology == nil {
			return nil, fmt.Errorf("unknown technology %q", name)
		}

		technologies = append(technologies, technicalAssetTechnology)
	}

	return technologies, nil
}

func (what TechnologyMap) PropagateAttributes() {
	technologyList := make([]Technology, 0)
	for name, value := range what {
		technology := new(Technology)
		*technology = value
		technology.Attributes = make(map[string]bool)

		what.propagateAttributes(name, technology.Attributes)
		technology.Attributes[name] = true
		technology.Name = name

		technologyList = append(technologyList, *technology)
	}

	for name := range what {
		delete(what, name)
	}

	for _, technology := range technologyList {
		what[technology.Name] = technology
	}
}

func (what TechnologyMap) propagateAttributes(name string, attributes map[string]bool) {
	tech, ok := what[name]
	if ok {
		what.propagateAttributes(tech.Parent, attributes)
	}

	for key, value := range tech.Attributes {
		attributes[key] = value
	}
}

func TechnicalAssetTechnologyValues(cfg technologyMapConfigReader) []TypeEnum {
	technologies := make(TechnologyMap)
	_ = technologies.LoadWithConfig(cfg, "technologies.yaml")
	technologies.PropagateAttributes()

	values := make([]TypeEnum, 0)
	for _, technology := range technologies {
		values = append(values, TypeEnum(technology))
	}

	return values
}
