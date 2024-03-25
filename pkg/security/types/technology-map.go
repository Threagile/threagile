package types

import (
	"embed"
	_ "embed"
	"fmt"
	"github.com/threagile/threagile/pkg/common"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

const (
	UnknownTechnology TechnicalAssetTechnology = iota
	ClientSystem
	Browser
	Desktop
	MobileApp
	DevOpsClient
	WebServer
	WebApplication
	ApplicationServer
	Database
	FileServer
	LocalFileSystem
	ERP
	CMS
	WebServiceREST
	WebServiceSOAP
	EJB
	SearchIndex
	SearchEngine
	ServiceRegistry
	ReverseProxy
	LoadBalancer
	BuildPipeline
	SourcecodeRepository
	ArtifactRegistry
	CodeInspectionPlatform
	Monitoring
	LDAPServer
	ContainerPlatform
	BatchProcessing
	EventListener
	IdentityProvider
	IdentityStoreLDAP
	IdentityStoreDatabase
	Tool
	CLI
	Task
	Function
	Gateway // TODO rename to API-Gateway to be more clear?
	IoTDevice
	MessageQueue
	StreamProcessing
	ServiceMesh
	DataLake
	BigDataPlatform
	ReportEngine
	AI
	MailServer
	Vault
	HSM
	WAF
	IDS
	IPS
	Scheduler
	Mainframe
	BlockStorage
	Library
)

//go:embed technologies.yaml
var supportFolder embed.FS

type TechnologyMap map[string]Technology

func (what TechnologyMap) LoadWithConfig(config common.Config, defaultFilename string) error {
	technologiesFilename := filepath.Join(config.AppFolder, defaultFilename)
	_, statError := os.Stat(technologiesFilename)
	if statError == nil {
		technologiesLoadError := what.LoadFromFile(technologiesFilename)
		if technologiesLoadError != nil {
			return fmt.Errorf("error loading technologies: %v", technologiesLoadError)
		}
	} else {
		technologiesLoadError := what.LoadDefault()
		if technologiesLoadError != nil {
			return fmt.Errorf("error loading technologies: %v", technologiesLoadError)
		}
	}

	if len(config.TechnologyFilename) > 0 {
		additionalTechnologies := make(TechnologyMap)
		loadError := additionalTechnologies.LoadFromFile(config.TechnologyFilename)
		if loadError != nil {
			return fmt.Errorf("error loading additional technologies from %q: %v", config.TechnologyFilename, loadError)
		}

		for name, technology := range additionalTechnologies {
			what[name] = technology
		}
	}

	return nil
}

func (what TechnologyMap) LoadDefault() error {
	defaultTechnologyFile, readError := supportFolder.ReadFile("technologies.yaml")
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
		return fmt.Errorf("error writing %q: %v", filename, writeError)
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
