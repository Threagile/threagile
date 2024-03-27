package main

import (
	"flag"
	"fmt"
	"github.com/threagile/threagile/pkg/security/types"
	"strings"
)

func main() {
	//	save := flag.Bool("save", false, "Save all technologies to technologies.yaml")
	load := flag.Bool("load", false, "Load all technologies from technologies.yaml")
	//	comp := flag.Bool("comp", false, "Compare all technologies from technologies.yaml to types.TechnicalAssetTechnologyValues()")
	flag.Parse()

	filename := flag.Arg(0)
	if filename == "" {
		filename = "technologies.yaml"
	}

	/*
		if *save {
			saveError := getTechnologies().Save(filename)
			if saveError != nil {
				fmt.Printf("error saving technologies: %v\n", saveError)
				return
			}
		}
	*/

	if *load {
		technologies := make(types.TechnologyMap)
		loadError := technologies.LoadFromFile(filename)
		if loadError != nil {
			fmt.Printf("error loading technologies: %v\n", loadError)
			return
		}
	}

	/*
		if *comp {
			savedTechnologies := make(types.TechnologyMap)
			loadError := savedTechnologies.LoadFromFile(filename)
			if loadError != nil {
				fmt.Printf("error loading technologies: %v\n", loadError)
				return
			}

			savedTechnologies.PropagateAttributes()
			compareTechnologies(savedTechnologies, getTechnologies())
		}
	*/
}

func compareTechnologies(savedTechnologies types.TechnologyMap, builtinTechnologies types.TechnologyMap) {
	for name, saved := range savedTechnologies {
		builtin, exists := builtinTechnologies[name]
		if !exists {
			fmt.Printf("saved technology %q not found in built-in technologies\n", name)
			continue
		}

		diffs := compareTechnology(saved, builtin)
		if len(diffs) > 0 {
			fmt.Printf("saved technology %q differs:\n%v\n", name, strings.Join(diffs, ""))
		}
	}

	for name := range builtinTechnologies {
		_, exists := savedTechnologies[name]
		if !exists {
			fmt.Printf("built-in technology %q not found in saved technologies\n", name)
			continue
		}
	}
}

func compareTechnology(savedTechnology types.Technology, builtinTechnology types.Technology) []string {
	diffs := make([]string, 0)

	if savedTechnology.Name != builtinTechnology.Name {
		diffs = append(diffs, fmt.Sprintf("    name: %q - %q\n", savedTechnology.Name, builtinTechnology.Name))
	}

	if savedTechnology.Parent != builtinTechnology.Parent {
		diffs = append(diffs, fmt.Sprintf("    parent: %q - %q\n", savedTechnology.Parent, builtinTechnology.Parent))
	}

	if savedTechnology.Description != builtinTechnology.Description {
		diffs = append(diffs, fmt.Sprintf("    description: %q - %q\n", savedTechnology.Description, builtinTechnology.Description))
	}

	for _, builtin := range builtinTechnology.Aliases {
		found := false
		for _, saved := range savedTechnology.Aliases {
			if saved == builtin {
				found = true
			}
		}

		if !found {
			diffs = append(diffs, fmt.Sprintf("    built-in alias %q missing in saved\n", builtin))
		}
	}

	for _, saved := range savedTechnology.Aliases {
		found := false
		for _, builtin := range builtinTechnology.Aliases {
			if saved == builtin {
				found = true
			}
		}

		if !found {
			diffs = append(diffs, fmt.Sprintf("    saved alias %q missing in built-in\n", saved))
		}
	}

	for _, builtin := range builtinTechnology.Examples {
		found := false
		for _, saved := range savedTechnology.Examples {
			if saved == builtin {
				found = true
			}
		}

		if !found {
			diffs = append(diffs, fmt.Sprintf("    built-in example %q missing in saved\n", builtin))
		}
	}

	for _, saved := range savedTechnology.Examples {
		found := false
		for _, builtin := range builtinTechnology.Examples {
			if saved == builtin {
				found = true
			}
		}

		if !found {
			diffs = append(diffs, fmt.Sprintf("    saved example %q missing in built-in\n", saved))
		}
	}

	for key, saved := range savedTechnology.Attributes {
		builtin, exists := builtinTechnology.Attributes[key]
		if !exists {
			diffs = append(diffs, fmt.Sprintf("    attribute %q missing in built-in\n", key))
			continue
		}

		if saved != builtin {
			diffs = append(diffs, fmt.Sprintf("    attribute %q: %v - %v\n", key, saved, builtin))
		}
	}

	for key := range builtinTechnology.Attributes {
		_, exists := savedTechnology.Attributes[key]
		if !exists {
			diffs = append(diffs, fmt.Sprintf("    attribute %q missing in built-in\n", key))
			continue
		}
	}

	return diffs
}

/*
func getTechnologies() types.TechnologyMap {
	technologies := make(types.TechnologyMap)
	for _, value := range types.TechnicalAssetTechnologyValues() {
		tech := value.(types.TechnicalAssetTechnology)

		technology := types.Technology{
			Name:        tech.String(),
			Description: tech.Explain(),
			Attributes:  make(map[string]bool),
		}

		if tech..GetAttribute(types.WebApplication) {
			technology.Attributes["web_application"] = true
		}

		if tech.GetAttribute(IsWebService) {
			technology.Attributes["web_service"] = true
		}

		if tech.IsIdentityRelated() {
			technology.Attributes["identity_related"] = true
		}

		if tech.IsSecurityControlRelated() {
			technology.Attributes["security_control_related"] = true
		}

		if tech.IsUnprotectedCommunicationsTolerated() {
			technology.Attributes["unprotected_communications_tolerated"] = true
		}

		if tech.IsUnnecessaryDataTolerated() {
			technology.Attributes["unnecessary_data_tolerated"] = true
		}

		if tech.IsCloseToHighValueTargetsTolerated() {
			technology.Attributes["close_to_high_value_targets_tolerated"] = true
		}

		if tech.IsClient() {
			technology.Attributes["client"] = true
		}

		if tech.IsUsuallyAbleToPropagateIdentityToOutgoingTargets() {
			technology.Attributes["propagate_identity_to_outgoing_targets"] = true
		}

		if tech.IsLessProtectedType() {
			technology.Attributes["less_protected_type"] = true
		}

		if tech.IsUsuallyProcessingEndUserRequests() {
			technology.Attributes["processing_end_user_requests"] = true
		}

		if tech.IsUsuallyStoringEndUserData() {
			technology.Attributes["storing_end_user_data"] = true
		}

		if tech.IsExclusivelyFrontendRelated() {
			technology.Attributes["frontend_related"] = true
		}

		if tech.IsExclusivelyBackendRelated() {
			technology.Attributes["backend_related"] = true
		}

		if tech.IsDevelopmentRelevant() {
			technology.Attributes["development_relevant"] = true
		}

		if tech.IsTrafficForwarding() {
			technology.Attributes["traffic_forwarding"] = true
		}

		if tech.IsEmbeddedComponent() {
			technology.Attributes["embedded_component"] = true
		}

		technologies[technology.Name] = technology
	}

	return technologies
}
*/
