package add_build_pipeline

import (
	"fmt"
	"github.com/threagile/threagile/model"
	"sort"
	"strings"
)

func GetMacroDetails() model.MacroDetails {
	return model.MacroDetails{
		ID:    "add-build-pipeline",
		Title: "Add Build Pipeline",
		Description: "This model macro adds a build pipeline (development client, build pipeline, artifact registry, container image registry, " +
			"source code repository, etc.) to the model.",
	}
}

var macroState = make(map[string][]string)
var questionsAnswered = make([]string, 0)
var codeInspectionUsed, containerTechUsed, withinTrustBoundary, createNewTrustBoundary bool

const createNewTrustBoundaryLabel = "CREATE NEW TRUST BOUNDARY"

var pushOrPull = []string{
	"Push-based Deployment (build pipeline deploys towards target asset)",
	"Pull-based Deployment (deployment target asset fetches deployment from registry)",
}

// TODO add question for type of machine (either physical, virtual, container, etc.)

func GetNextQuestion() (nextQuestion model.MacroQuestion, err error) {
	counter := len(questionsAnswered)
	if counter > 3 && !codeInspectionUsed {
		counter++
	}
	if counter > 5 && !containerTechUsed {
		counter += 2
	}
	if counter > 12 && !withinTrustBoundary {
		counter++
	}
	if counter > 13 && !createNewTrustBoundary {
		counter++
	}
	switch counter {
	case 0:
		return model.MacroQuestion{
			ID:              "source-repository",
			Title:           "What product is used as the sourcecode repository?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Git",
		}, nil
	case 1:
		return model.MacroQuestion{
			ID:              "build-pipeline",
			Title:           "What product is used as the build pipeline?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Jenkins",
		}, nil
	case 2:
		return model.MacroQuestion{
			ID:              "artifact-registry",
			Title:           "What product is used as the artifact registry?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Nexus",
		}, nil
	case 3:
		return model.MacroQuestion{
			ID:              "code-inspection-used",
			Title:           "Are code inspection platforms (like SonarQube) used?",
			Description:     "This affects whether code inspection platform are added.",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 4:
		return model.MacroQuestion{
			ID:              "code-inspection-platform",
			Title:           "What product is used as the code inspection platform?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "SonarQube",
		}, nil
	case 5:
		return model.MacroQuestion{
			ID:              "container-technology-used",
			Title:           "Is container technology (like Docker) used?",
			Description:     "This affects whether container registries are added.",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 6:
		return model.MacroQuestion{
			ID:              "container-registry",
			Title:           "What product is used as the container registry?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Docker",
		}, nil
	case 7:
		return model.MacroQuestion{
			ID:              "container-platform",
			Title:           "What product is used as the container platform (for orchestration and runtime)?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "Kubernetes",
		}, nil
	case 8:
		return model.MacroQuestion{
			ID:              "internet",
			Title:           "Are build pipeline components exposed on the internet?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 9:
		return model.MacroQuestion{
			ID:              "multi-tenant",
			Title:           "Are build pipeline components used by multiple tenants?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 10:
		return model.MacroQuestion{
			ID:              "encryption",
			Title:           "Are build pipeline components encrypted?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 11:
		possibleAnswers := make([]string, 0)
		for id, _ := range model.ParsedModelRoot.TechnicalAssets {
			possibleAnswers = append(possibleAnswers, id)
		}
		sort.Strings(possibleAnswers)
		if len(possibleAnswers) > 0 {
			return model.MacroQuestion{
				ID:              "deploy-targets",
				Title:           "Select all technical assets where the build pipeline deploys to:",
				Description:     "This affects the communication links being generated.",
				PossibleAnswers: possibleAnswers,
				MultiSelect:     true,
				DefaultAnswer:   "",
			}, nil
		}
	case 12:
		return model.MacroQuestion{
			ID:              "within-trust-boundary",
			Title:           "Are the server-side components of the build pipeline components within a network trust boundary?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 13:
		possibleAnswers := []string{createNewTrustBoundaryLabel}
		for id, trustBoundary := range model.ParsedModelRoot.TrustBoundaries {
			if trustBoundary.Type.IsNetworkBoundary() {
				possibleAnswers = append(possibleAnswers, id)
			}
		}
		sort.Strings(possibleAnswers)
		return model.MacroQuestion{
			ID:              "selected-trust-boundary",
			Title:           "Choose from the list of existing network trust boundaries or create a new one?",
			Description:     "",
			PossibleAnswers: possibleAnswers,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	case 14:
		return model.MacroQuestion{
			ID:          "new-trust-boundary-type",
			Title:       "Of which type shall the new trust boundary be?",
			Description: "",
			PossibleAnswers: []string{model.NetworkOnPrem.String(),
				model.NetworkDedicatedHoster.String(),
				model.NetworkVirtualLAN.String(),
				model.NetworkCloudProvider.String(),
				model.NetworkCloudSecurityGroup.String(),
				model.NetworkPolicyNamespaceIsolation.String()},
			MultiSelect:   false,
			DefaultAnswer: model.NetworkOnPrem.String(),
		}, nil
	case 15:
		return model.MacroQuestion{
			ID:              "push-or-pull",
			Title:           "What type of deployment strategy is used?",
			Description:     "Push-based deployments are more classic ones and pull-based are more GitOps-like ones.",
			PossibleAnswers: pushOrPull,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	case 16:
		return model.MacroQuestion{
			ID:              "owner",
			Title:           "Who is the owner of the build pipeline and runtime assets?",
			Description:     "This name affects the technical asset's and data asset's owner.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	}
	return model.NoMoreQuestions(), nil
}

func ApplyAnswer(questionID string, answer ...string) (message string, validResult bool, err error) {
	macroState[questionID] = answer
	questionsAnswered = append(questionsAnswered, questionID)
	if questionID == "code-inspection-used" {
		codeInspectionUsed = strings.ToLower(macroState["code-inspection-used"][0]) == "yes"
	} else if questionID == "container-technology-used" {
		containerTechUsed = strings.ToLower(macroState["container-technology-used"][0]) == "yes"
	} else if questionID == "within-trust-boundary" {
		withinTrustBoundary = strings.ToLower(macroState["within-trust-boundary"][0]) == "yes"
	} else if questionID == "selected-trust-boundary" {
		createNewTrustBoundary = strings.ToLower(macroState["selected-trust-boundary"][0]) == strings.ToLower(createNewTrustBoundaryLabel)
	}
	return "Answer processed", true, nil
}

func GoBack() (message string, validResult bool, err error) {
	if len(questionsAnswered) == 0 {
		return "Cannot go back further", false, nil
	}
	lastQuestionID := questionsAnswered[len(questionsAnswered)-1]
	questionsAnswered = questionsAnswered[:len(questionsAnswered)-1]
	delete(macroState, lastQuestionID)
	return "Undo successful", true, nil
}

func GetFinalChangeImpact(modelInput *model.ModelInput) (changes []string, message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult, err = applyChange(modelInput, &changeLogCollector, true)
	return changeLogCollector, message, validResult, err
}

func Execute(modelInput *model.ModelInput) (message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult, err = applyChange(modelInput, &changeLogCollector, false)
	return message, validResult, err
}

func applyChange(modelInput *model.ModelInput, changeLogCollector *[]string, dryRun bool) (message string, validResult bool, err error) {
	var serverSideTechAssets = make([]string, 0)
	// ################################################
	model.AddTagToModelInput(modelInput, macroState["source-repository"][0], dryRun, changeLogCollector)
	model.AddTagToModelInput(modelInput, macroState["build-pipeline"][0], dryRun, changeLogCollector)
	model.AddTagToModelInput(modelInput, macroState["artifact-registry"][0], dryRun, changeLogCollector)
	if containerTechUsed {
		model.AddTagToModelInput(modelInput, macroState["container-registry"][0], dryRun, changeLogCollector)
		model.AddTagToModelInput(modelInput, macroState["container-platform"][0], dryRun, changeLogCollector)
	}
	if codeInspectionUsed {
		model.AddTagToModelInput(modelInput, macroState["code-inspection-platform"][0], dryRun, changeLogCollector)
	}

	sourceRepoID := model.MakeID(macroState["source-repository"][0]) + "-sourcecode-repository"
	buildPipelineID := model.MakeID(macroState["build-pipeline"][0]) + "-build-pipeline"
	artifactRegistryID := model.MakeID(macroState["artifact-registry"][0]) + "-artifact-registry"
	containerRepoID, containerPlatformID, containerSharedRuntimeID := "", "", ""
	if containerTechUsed {
		containerRepoID = model.MakeID(macroState["container-registry"][0]) + "-container-registry"
		containerPlatformID = model.MakeID(macroState["container-platform"][0]) + "-container-platform"
		containerSharedRuntimeID = model.MakeID(macroState["container-platform"][0]) + "-container-runtime"
	}
	codeInspectionPlatformID := ""
	if codeInspectionUsed {
		codeInspectionPlatformID = model.MakeID(macroState["code-inspection-platform"][0]) + "-code-inspection-platform"
	}
	owner := macroState["owner"][0]

	if _, exists := model.ParsedModelRoot.DataAssets["Sourcecode"]; !exists {
		//fmt.Println("Adding data asset:", "sourcecode") // ################################################
		dataAsset := model.InputDataAsset{
			ID:              "sourcecode",
			Description:     "Sourcecode to build the application components from",
			Usage:           model.DevOps.String(),
			Tags:            []string{},
			Origin:          "",
			Owner:           owner,
			Quantity:        model.Few.String(),
			Confidentiality: model.Confidential.String(),
			Integrity:       model.Critical.String(),
			Availability:    model.Important.String(),
			Justification_cia_rating: "Sourcecode is at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
		}
		*changeLogCollector = append(*changeLogCollector, "adding data asset: sourcecode")
		if !dryRun {
			modelInput.Data_assets["Sourcecode"] = dataAsset
		}
	}

	if _, exists := model.ParsedModelRoot.DataAssets["Deployment"]; !exists {
		//fmt.Println("Adding data asset:", "deployment") // ################################################
		dataAsset := model.InputDataAsset{
			ID:              "deployment",
			Description:     "Deployment unit being installed/shipped",
			Usage:           model.DevOps.String(),
			Tags:            []string{},
			Origin:          "",
			Owner:           owner,
			Quantity:        model.VeryFew.String(),
			Confidentiality: model.Confidential.String(),
			Integrity:       model.Critical.String(),
			Availability:    model.Important.String(),
			Justification_cia_rating: "Deployment units are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
		}
		*changeLogCollector = append(*changeLogCollector, "adding data asset: deployment")
		if !dryRun {
			modelInput.Data_assets["Deployment"] = dataAsset
		}
	}

	id := "development-client"
	if _, exists := model.ParsedModelRoot.TechnicalAssets[id]; !exists {
		//fmt.Println("Adding technical asset:", id) // ################################################
		encryption := model.NoneEncryption.String()
		if strings.ToLower(macroState["encryption"][0]) == "yes" {
			encryption = model.Transparent.String()
		}

		commLinks := make(map[string]model.InputCommunicationLink)
		commLinks["Sourcecode Repository Traffic"] = model.InputCommunicationLink{
			Target:                   sourceRepoID,
			Description:              "Sourcecode Repository Traffic",
			Protocol:                 model.HTTPS.String(),
			Authentication:           model.Credentials.String(),
			Authorization:            model.EnduserIdentityPropagation.String(),
			Tags:                     []string{},
			VPN:                      false,
			IP_filtered:              false,
			Readonly:                 false,
			Usage:                    model.DevOps.String(),
			Data_assets_sent:         []string{"sourcecode"},
			Data_assets_received:     []string{"sourcecode"},
			Diagram_tweak_weight:     0,
			Diagram_tweak_constraint: false,
		}
		commLinks["Build Pipeline Traffic"] = model.InputCommunicationLink{
			Target:                   buildPipelineID,
			Description:              "Build Pipeline Traffic",
			Protocol:                 model.HTTPS.String(),
			Authentication:           model.Credentials.String(),
			Authorization:            model.EnduserIdentityPropagation.String(),
			Tags:                     []string{},
			VPN:                      false,
			IP_filtered:              false,
			Readonly:                 true,
			Usage:                    model.DevOps.String(),
			Data_assets_sent:         nil,
			Data_assets_received:     []string{"deployment"},
			Diagram_tweak_weight:     0,
			Diagram_tweak_constraint: false,
		}
		commLinks["Artifact Registry Traffic"] = model.InputCommunicationLink{
			Target:                   artifactRegistryID,
			Description:              "Artifact Registry Traffic",
			Protocol:                 model.HTTPS.String(),
			Authentication:           model.Credentials.String(),
			Authorization:            model.EnduserIdentityPropagation.String(),
			Tags:                     []string{},
			VPN:                      false,
			IP_filtered:              false,
			Readonly:                 true,
			Usage:                    model.DevOps.String(),
			Data_assets_sent:         nil,
			Data_assets_received:     []string{"deployment"},
			Diagram_tweak_weight:     0,
			Diagram_tweak_constraint: false,
		}
		if containerTechUsed {
			commLinks["Container Registry Traffic"] = model.InputCommunicationLink{
				Target:                   containerRepoID,
				Description:              "Container Registry Traffic",
				Protocol:                 model.HTTPS.String(),
				Authentication:           model.Credentials.String(),
				Authorization:            model.EnduserIdentityPropagation.String(),
				Tags:                     []string{},
				VPN:                      false,
				IP_filtered:              false,
				Readonly:                 false,
				Usage:                    model.DevOps.String(),
				Data_assets_sent:         []string{"deployment"},
				Data_assets_received:     []string{"deployment"},
				Diagram_tweak_weight:     0,
				Diagram_tweak_constraint: false,
			}
			commLinks["Container Platform Traffic"] = model.InputCommunicationLink{
				Target:                   containerPlatformID,
				Description:              "Container Platform Traffic",
				Protocol:                 model.HTTPS.String(),
				Authentication:           model.Credentials.String(),
				Authorization:            model.EnduserIdentityPropagation.String(),
				Tags:                     []string{},
				VPN:                      false,
				IP_filtered:              false,
				Readonly:                 false,
				Usage:                    model.DevOps.String(),
				Data_assets_sent:         []string{"deployment"},
				Data_assets_received:     []string{"deployment"},
				Diagram_tweak_weight:     0,
				Diagram_tweak_constraint: false,
			}
		}
		if codeInspectionUsed {
			commLinks["Code Inspection Platform Traffic"] = model.InputCommunicationLink{
				Target:                   codeInspectionPlatformID,
				Description:              "Code Inspection Platform Traffic",
				Protocol:                 model.HTTPS.String(),
				Authentication:           model.Credentials.String(),
				Authorization:            model.EnduserIdentityPropagation.String(),
				Tags:                     []string{},
				VPN:                      false,
				IP_filtered:              false,
				Readonly:                 true,
				Usage:                    model.DevOps.String(),
				Data_assets_sent:         nil,
				Data_assets_received:     []string{"sourcecode"},
				Diagram_tweak_weight:     0,
				Diagram_tweak_constraint: false,
			}
		}

		techAsset := model.InputTechnicalAsset{
			ID:                         id,
			Description:                "Development Client",
			Type:                       model.ExternalEntity.String(),
			Usage:                      model.DevOps.String(),
			Used_as_client_by_human:    true,
			Out_of_scope:               true,
			Justification_out_of_scope: "Development client is not directly in-scope of the application.",
			Size:                       model.System.String(),
			Technology:                 model.DevOpsClient.String(),
			Tags:                       []string{},
			Internet:                   strings.ToLower(macroState["internet"][0]) == "yes",
			Machine:                    model.Physical.String(),
			Encryption:                 encryption,
			Owner:                      owner,
			Confidentiality:            model.Confidential.String(),
			Integrity:                  model.Critical.String(),
			Availability:               model.Important.String(),
			Justification_cia_rating: "Sourcecode processing components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			Multi_tenant:           false,
			Redundant:              false,
			Custom_developed_parts: false,
			Data_assets_processed:  []string{"sourcecode", "deployment"},
			Data_assets_stored:     []string{"sourcecode", "deployment"},
			Data_formats_accepted:  []string{"file"},
			Communication_links:    commLinks,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.Technical_assets["Development Client"] = techAsset
		}
	}

	id = sourceRepoID
	if _, exists := model.ParsedModelRoot.TechnicalAssets[id]; !exists {
		//fmt.Println("Adding technical asset:", id) // ################################################
		serverSideTechAssets = append(serverSideTechAssets, id)
		encryption := model.NoneEncryption.String()
		if strings.ToLower(macroState["encryption"][0]) == "yes" {
			encryption = model.Transparent.String()
		}
		techAsset := model.InputTechnicalAsset{
			ID:                         id,
			Description:                macroState["source-repository"][0] + " Sourcecode Repository",
			Type:                       model.Process.String(),
			Usage:                      model.DevOps.String(),
			Used_as_client_by_human:    false,
			Out_of_scope:               false,
			Justification_out_of_scope: "",
			Size:                       model.Service.String(),
			Technology:                 model.SourcecodeRepository.String(),
			Tags:                       []string{model.NormalizeTag(macroState["source-repository"][0])},
			Internet:                   strings.ToLower(macroState["internet"][0]) == "yes",
			Machine:                    model.Virtual.String(),
			Encryption:                 encryption,
			Owner:                      owner,
			Confidentiality:            model.Confidential.String(),
			Integrity:                  model.Critical.String(),
			Availability:               model.Important.String(),
			Justification_cia_rating: "Sourcecode processing components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			Multi_tenant:           strings.ToLower(macroState["multi-tenant"][0]) == "yes",
			Redundant:              false,
			Custom_developed_parts: false,
			Data_assets_processed:  []string{"sourcecode"},
			Data_assets_stored:     []string{"sourcecode"},
			Data_formats_accepted:  []string{"file"},
			Communication_links:    nil,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.Technical_assets[macroState["source-repository"][0]+" Sourcecode Repository"] = techAsset
		}
	}

	if containerTechUsed {
		id = containerRepoID
		if _, exists := model.ParsedModelRoot.TechnicalAssets[id]; !exists {
			//fmt.Println("Adding technical asset:", id) // ################################################
			serverSideTechAssets = append(serverSideTechAssets, id)
			encryption := model.NoneEncryption.String()
			if strings.ToLower(macroState["encryption"][0]) == "yes" {
				encryption = model.Transparent.String()
			}
			techAsset := model.InputTechnicalAsset{
				ID:                         id,
				Description:                macroState["container-registry"][0] + " Container Registry",
				Type:                       model.Process.String(),
				Usage:                      model.DevOps.String(),
				Used_as_client_by_human:    false,
				Out_of_scope:               false,
				Justification_out_of_scope: "",
				Size:                       model.Service.String(),
				Technology:                 model.ArtifactRegistry.String(),
				Tags:                       []string{model.NormalizeTag(macroState["container-registry"][0])},
				Internet:                   strings.ToLower(macroState["internet"][0]) == "yes",
				Machine:                    model.Virtual.String(),
				Encryption:                 encryption,
				Owner:                      owner,
				Confidentiality:            model.Confidential.String(),
				Integrity:                  model.Critical.String(),
				Availability:               model.Important.String(),
				Justification_cia_rating: "Container registry components are at least rated as 'critical' in terms of integrity, because any " +
					"malicious modification of it might lead to a backdoored production system.",
				Multi_tenant:           strings.ToLower(macroState["multi-tenant"][0]) == "yes",
				Redundant:              false,
				Custom_developed_parts: false,
				Data_assets_processed:  []string{"deployment"},
				Data_assets_stored:     []string{"deployment"},
				Data_formats_accepted:  []string{"file"},
				Communication_links:    nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
			if !dryRun {
				modelInput.Technical_assets[macroState["container-registry"][0]+" Container Registry"] = techAsset
			}
		}

		id = containerPlatformID
		if _, exists := model.ParsedModelRoot.TechnicalAssets[id]; !exists {
			//fmt.Println("Adding technical asset:", id) // ################################################
			serverSideTechAssets = append(serverSideTechAssets, id)
			encryption := model.NoneEncryption.String()
			if strings.ToLower(macroState["encryption"][0]) == "yes" {
				encryption = model.Transparent.String()
			}
			techAsset := model.InputTechnicalAsset{
				ID:                         id,
				Description:                macroState["container-platform"][0] + " Container Platform",
				Type:                       model.Process.String(),
				Usage:                      model.DevOps.String(),
				Used_as_client_by_human:    false,
				Out_of_scope:               false,
				Justification_out_of_scope: "",
				Size:                       model.System.String(),
				Technology:                 model.ContainerPlatform.String(),
				Tags:                       []string{model.NormalizeTag(macroState["container-platform"][0])},
				Internet:                   strings.ToLower(macroState["internet"][0]) == "yes",
				Machine:                    model.Virtual.String(),
				Encryption:                 encryption,
				Owner:                      owner,
				Confidentiality:            model.Confidential.String(),
				Integrity:                  model.MissionCritical.String(),
				Availability:               model.MissionCritical.String(),
				Justification_cia_rating: "Container platform components are rated as 'mission-critical' in terms of integrity and availability, because any " +
					"malicious modification of it might lead to a backdoored production system.",
				Multi_tenant:           strings.ToLower(macroState["multi-tenant"][0]) == "yes",
				Redundant:              false,
				Custom_developed_parts: false,
				Data_assets_processed:  []string{"deployment"},
				Data_assets_stored:     []string{"deployment"},
				Data_formats_accepted:  []string{"file"},
				Communication_links:    nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
			if !dryRun {
				modelInput.Technical_assets[macroState["container-platform"][0]+" Container Platform"] = techAsset
			}
		}
	}

	id = buildPipelineID
	if _, exists := model.ParsedModelRoot.TechnicalAssets[id]; !exists {
		//fmt.Println("Adding technical asset:", id) // ################################################
		serverSideTechAssets = append(serverSideTechAssets, id)
		encryption := model.NoneEncryption.String()
		if strings.ToLower(macroState["encryption"][0]) == "yes" {
			encryption = model.Transparent.String()
		}

		commLinks := make(map[string]model.InputCommunicationLink)
		commLinks["Sourcecode Repository Traffic"] = model.InputCommunicationLink{
			Target:                   sourceRepoID,
			Description:              "Sourcecode Repository Traffic",
			Protocol:                 model.HTTPS.String(),
			Authentication:           model.Credentials.String(),
			Authorization:            model.TechnicalUser.String(),
			Tags:                     []string{},
			VPN:                      false,
			IP_filtered:              false,
			Readonly:                 true,
			Usage:                    model.DevOps.String(),
			Data_assets_sent:         nil,
			Data_assets_received:     []string{"sourcecode"},
			Diagram_tweak_weight:     0,
			Diagram_tweak_constraint: false,
		}
		commLinks["Artifact Registry Traffic"] = model.InputCommunicationLink{
			Target:                   artifactRegistryID,
			Description:              "Artifact Registry Traffic",
			Protocol:                 model.HTTPS.String(),
			Authentication:           model.Credentials.String(),
			Authorization:            model.TechnicalUser.String(),
			Tags:                     []string{},
			VPN:                      false,
			IP_filtered:              false,
			Readonly:                 false,
			Usage:                    model.DevOps.String(),
			Data_assets_sent:         []string{"deployment"},
			Data_assets_received:     []string{"deployment"},
			Diagram_tweak_weight:     0,
			Diagram_tweak_constraint: false,
		}
		if containerTechUsed {
			commLinks["Container Registry Traffic"] = model.InputCommunicationLink{
				Target:                   containerRepoID,
				Description:              "Container Registry Traffic",
				Protocol:                 model.HTTPS.String(),
				Authentication:           model.Credentials.String(),
				Authorization:            model.TechnicalUser.String(),
				Tags:                     []string{},
				VPN:                      false,
				IP_filtered:              false,
				Readonly:                 false,
				Usage:                    model.DevOps.String(),
				Data_assets_sent:         []string{"deployment"},
				Data_assets_received:     []string{"deployment"},
				Diagram_tweak_weight:     0,
				Diagram_tweak_constraint: false,
			}
			if macroState["push-or-pull"][0] == pushOrPull[0] { // Push
				commLinks["Container Platform Push"] = model.InputCommunicationLink{
					Target:                   containerPlatformID,
					Description:              "Container Platform Push",
					Protocol:                 model.HTTPS.String(),
					Authentication:           model.Credentials.String(),
					Authorization:            model.TechnicalUser.String(),
					Tags:                     []string{},
					VPN:                      false,
					IP_filtered:              false,
					Readonly:                 false,
					Usage:                    model.DevOps.String(),
					Data_assets_sent:         []string{"deployment"},
					Data_assets_received:     []string{"deployment"},
					Diagram_tweak_weight:     0,
					Diagram_tweak_constraint: false,
				}
			} else { // Pull
				commLinkPull := model.InputCommunicationLink{
					Target:                   containerRepoID,
					Description:              "Container Platform Pull",
					Protocol:                 model.HTTPS.String(),
					Authentication:           model.Credentials.String(),
					Authorization:            model.TechnicalUser.String(),
					Tags:                     []string{},
					VPN:                      false,
					IP_filtered:              false,
					Readonly:                 true,
					Usage:                    model.DevOps.String(),
					Data_assets_sent:         nil,
					Data_assets_received:     []string{"deployment"},
					Diagram_tweak_weight:     0,
					Diagram_tweak_constraint: false,
				}
				if !dryRun {
					titleOfTargetAsset := macroState["container-platform"][0] + " Container Platform"
					containerPlatform := modelInput.Technical_assets[titleOfTargetAsset]
					if containerPlatform.Communication_links == nil {
						containerPlatform.Communication_links = make(map[string]model.InputCommunicationLink, 0)
					}
					containerPlatform.Communication_links["Container Platform Pull"] = commLinkPull
					modelInput.Technical_assets[titleOfTargetAsset] = containerPlatform
				}
			}
		}
		if codeInspectionUsed {
			commLinks["Code Inspection Platform Traffic"] = model.InputCommunicationLink{
				Target:                   codeInspectionPlatformID,
				Description:              "Code Inspection Platform Traffic",
				Protocol:                 model.HTTPS.String(),
				Authentication:           model.Credentials.String(),
				Authorization:            model.TechnicalUser.String(),
				Tags:                     []string{},
				VPN:                      false,
				IP_filtered:              false,
				Readonly:                 false,
				Usage:                    model.DevOps.String(),
				Data_assets_sent:         []string{"sourcecode"},
				Data_assets_received:     []string{},
				Diagram_tweak_weight:     0,
				Diagram_tweak_constraint: false,
			}
		}
		// The individual deployments
		for _, deployTargetID := range macroState["deploy-targets"] { // add a connection to each deployment target
			//fmt.Println("Adding deployment flow to:", deployTargetID)
			if containerTechUsed {
				if !dryRun {
					containerPlatform := modelInput.Technical_assets[macroState["container-platform"][0]+" Container Platform"]
					if containerPlatform.Communication_links == nil {
						containerPlatform.Communication_links = make(map[string]model.InputCommunicationLink, 0)
					}
					containerPlatform.Communication_links["Container Spawning ("+deployTargetID+")"] = model.InputCommunicationLink{
						Target:                   deployTargetID,
						Description:              "Container Spawning " + deployTargetID,
						Protocol:                 model.ContainerSpawning.String(),
						Authentication:           model.NoneAuthentication.String(),
						Authorization:            model.NoneAuthorization.String(),
						Tags:                     []string{},
						VPN:                      false,
						IP_filtered:              false,
						Readonly:                 false,
						Usage:                    model.DevOps.String(),
						Data_assets_sent:         []string{"deployment"},
						Data_assets_received:     nil,
						Diagram_tweak_weight:     0,
						Diagram_tweak_constraint: false,
					}
					modelInput.Technical_assets[macroState["container-platform"][0]+" Container Platform"] = containerPlatform
				}
			} else { // No Containers used
				if macroState["push-or-pull"][0] == pushOrPull[0] { // Push
					commLinks["Deployment Push ("+deployTargetID+")"] = model.InputCommunicationLink{
						Target:                   deployTargetID,
						Description:              "Deployment Push to " + deployTargetID,
						Protocol:                 model.SSH.String(),
						Authentication:           model.ClientCertificate.String(),
						Authorization:            model.TechnicalUser.String(),
						Tags:                     []string{},
						VPN:                      false,
						IP_filtered:              false,
						Readonly:                 false,
						Usage:                    model.DevOps.String(),
						Data_assets_sent:         []string{"deployment"},
						Data_assets_received:     nil,
						Diagram_tweak_weight:     0,
						Diagram_tweak_constraint: false,
					}
				} else { // Pull
					pullFromWhere := artifactRegistryID
					commLinkPull := model.InputCommunicationLink{
						Target:                   pullFromWhere,
						Description:              "Deployment Pull from " + deployTargetID,
						Protocol:                 model.HTTPS.String(),
						Authentication:           model.Credentials.String(),
						Authorization:            model.TechnicalUser.String(),
						Tags:                     []string{},
						VPN:                      false,
						IP_filtered:              false,
						Readonly:                 true,
						Usage:                    model.DevOps.String(),
						Data_assets_sent:         nil,
						Data_assets_received:     []string{"deployment"},
						Diagram_tweak_weight:     0,
						Diagram_tweak_constraint: false,
					}
					if !dryRun {
						// take care to lookup by title (as keyed in input YAML by title and only in parsed model representation by ID)
						titleOfTargetAsset := model.ParsedModelRoot.TechnicalAssets[deployTargetID].Title
						x := modelInput.Technical_assets[titleOfTargetAsset]
						if x.Communication_links == nil {
							x.Communication_links = make(map[string]model.InputCommunicationLink, 0)
						}
						x.Communication_links["Deployment Pull ("+deployTargetID+")"] = commLinkPull
						modelInput.Technical_assets[titleOfTargetAsset] = x
					}

				}
			}

			// don't forget to also add the "deployment" data asset as stored on the target
			targetAssetTitle := model.ParsedModelRoot.TechnicalAssets[deployTargetID].Title
			assetsStored := make([]string, 0)
			if modelInput.Technical_assets[targetAssetTitle].Data_assets_stored != nil {
				for _, val := range modelInput.Technical_assets[targetAssetTitle].Data_assets_stored {
					assetsStored = append(assetsStored, fmt.Sprintf("%v", val))
				}
			}
			mergedArrays := make([]string, 0)
			for _, val := range assetsStored {
				mergedArrays = append(mergedArrays, fmt.Sprintf("%v", val))
			}
			mergedArrays = append(mergedArrays, "deployment")
			if !dryRun {
				x := modelInput.Technical_assets[targetAssetTitle]
				x.Data_assets_stored = mergedArrays
				modelInput.Technical_assets[targetAssetTitle] = x
			}
		}

		techAsset := model.InputTechnicalAsset{
			ID:                         id,
			Description:                macroState["build-pipeline"][0] + " Build Pipeline",
			Type:                       model.Process.String(),
			Usage:                      model.DevOps.String(),
			Used_as_client_by_human:    false,
			Out_of_scope:               false,
			Justification_out_of_scope: "",
			Size:                       model.Service.String(),
			Technology:                 model.BuildPipeline.String(),
			Tags:                       []string{model.NormalizeTag(macroState["build-pipeline"][0])},
			Internet:                   strings.ToLower(macroState["internet"][0]) == "yes",
			Machine:                    model.Virtual.String(),
			Encryption:                 encryption,
			Owner:                      owner,
			Confidentiality:            model.Confidential.String(),
			Integrity:                  model.Critical.String(),
			Availability:               model.Important.String(),
			Justification_cia_rating: "Build pipeline components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			Multi_tenant:           strings.ToLower(macroState["multi-tenant"][0]) == "yes",
			Redundant:              false,
			Custom_developed_parts: false,
			Data_assets_processed:  []string{"sourcecode", "deployment"},
			Data_assets_stored:     []string{"sourcecode", "deployment"},
			Data_formats_accepted:  []string{"file"},
			Communication_links:    commLinks,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.Technical_assets[macroState["build-pipeline"][0]+" Build Pipeline"] = techAsset
		}
	}

	id = artifactRegistryID
	if _, exists := model.ParsedModelRoot.TechnicalAssets[id]; !exists {
		//fmt.Println("Adding technical asset:", id) // ################################################
		serverSideTechAssets = append(serverSideTechAssets, id)
		encryption := model.NoneEncryption.String()
		if strings.ToLower(macroState["encryption"][0]) == "yes" {
			encryption = model.Transparent.String()
		}
		techAsset := model.InputTechnicalAsset{
			ID:                         id,
			Description:                macroState["artifact-registry"][0] + " Artifact Registry",
			Type:                       model.Process.String(),
			Usage:                      model.DevOps.String(),
			Used_as_client_by_human:    false,
			Out_of_scope:               false,
			Justification_out_of_scope: "",
			Size:                       model.Service.String(),
			Technology:                 model.ArtifactRegistry.String(),
			Tags:                       []string{model.NormalizeTag(macroState["artifact-registry"][0])},
			Internet:                   strings.ToLower(macroState["internet"][0]) == "yes",
			Machine:                    model.Virtual.String(),
			Encryption:                 encryption,
			Owner:                      owner,
			Confidentiality:            model.Confidential.String(),
			Integrity:                  model.Critical.String(),
			Availability:               model.Important.String(),
			Justification_cia_rating: "Artifact registry components are at least rated as 'critical' in terms of integrity, because any " +
				"malicious modification of it might lead to a backdoored production system.",
			Multi_tenant:           strings.ToLower(macroState["multi-tenant"][0]) == "yes",
			Redundant:              false,
			Custom_developed_parts: false,
			Data_assets_processed:  []string{"sourcecode", "deployment"},
			Data_assets_stored:     []string{"sourcecode", "deployment"},
			Data_formats_accepted:  []string{"file"},
			Communication_links:    nil,
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
		if !dryRun {
			modelInput.Technical_assets[macroState["artifact-registry"][0]+" Artifact Registry"] = techAsset
		}
	}

	if codeInspectionUsed {
		id = codeInspectionPlatformID
		if _, exists := model.ParsedModelRoot.TechnicalAssets[id]; !exists {
			//fmt.Println("Adding technical asset:", id) // ################################################
			serverSideTechAssets = append(serverSideTechAssets, id)
			encryption := model.NoneEncryption.String()
			if strings.ToLower(macroState["encryption"][0]) == "yes" {
				encryption = model.Transparent.String()
			}
			techAsset := model.InputTechnicalAsset{
				ID:                         id,
				Description:                macroState["code-inspection-platform"][0] + " Code Inspection Platform",
				Type:                       model.Process.String(),
				Usage:                      model.DevOps.String(),
				Used_as_client_by_human:    false,
				Out_of_scope:               false,
				Justification_out_of_scope: "",
				Size:                       model.Service.String(),
				Technology:                 model.CodeInspectionPlatform.String(),
				Tags:                       []string{model.NormalizeTag(macroState["code-inspection-platform"][0])},
				Internet:                   strings.ToLower(macroState["internet"][0]) == "yes",
				Machine:                    model.Virtual.String(),
				Encryption:                 encryption,
				Owner:                      owner,
				Confidentiality:            model.Confidential.String(),
				Integrity:                  model.Important.String(),
				Availability:               model.Operational.String(),
				Justification_cia_rating: "Sourcecode inspection platforms are rated at least 'important' in terms of integrity, because any " +
					"malicious modification of it might lead to vulnerabilities found by the scanner engine not being shown.",
				Multi_tenant:           strings.ToLower(macroState["multi-tenant"][0]) == "yes",
				Redundant:              false,
				Custom_developed_parts: false,
				Data_assets_processed:  []string{"sourcecode"},
				Data_assets_stored:     []string{"sourcecode"},
				Data_formats_accepted:  []string{"file"},
				Communication_links:    nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+id)
			if !dryRun {
				modelInput.Technical_assets[macroState["code-inspection-platform"][0]+" Code Inspection Platform"] = techAsset
			}
		}
	}

	if withinTrustBoundary {
		if createNewTrustBoundary {
			trustBoundaryType := macroState["new-trust-boundary-type"][0]
			//fmt.Println("Adding new trust boundary of type:", trustBoundaryType)
			title := "DevOps Network"
			trustBoundary := model.InputTrustBoundary{
				ID:                      "devops-network",
				Description:             "DevOps Network",
				Type:                    trustBoundaryType,
				Tags:                    []string{},
				Technical_assets_inside: serverSideTechAssets,
				Trust_boundaries_nested: nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding trust boundary: devops-network")
			if !dryRun {
				modelInput.Trust_boundaries[title] = trustBoundary
			}
		} else {
			existingTrustBoundaryToAddTo := macroState["selected-trust-boundary"][0]
			//fmt.Println("Adding to existing trust boundary:", existingTrustBoundaryToAddTo)
			title := model.ParsedModelRoot.TrustBoundaries[existingTrustBoundaryToAddTo].Title
			assetsInside := make([]string, 0)
			if modelInput.Trust_boundaries[title].Technical_assets_inside != nil {
				vals := modelInput.Trust_boundaries[title].Technical_assets_inside
				for _, val := range vals {
					assetsInside = append(assetsInside, fmt.Sprintf("%v", val))
				}
			}
			mergedArrays := make([]string, 0)
			for _, val := range assetsInside {
				mergedArrays = append(mergedArrays, fmt.Sprintf("%v", val))
			}
			mergedArrays = append(mergedArrays, serverSideTechAssets...)
			*changeLogCollector = append(*changeLogCollector, "filling existing trust boundary: "+existingTrustBoundaryToAddTo)
			if !dryRun {
				if modelInput.Trust_boundaries == nil {
					modelInput.Trust_boundaries = make(map[string]model.InputTrustBoundary, 0)
				}
				tb := modelInput.Trust_boundaries[title]
				tb.Technical_assets_inside = mergedArrays
				modelInput.Trust_boundaries[title] = tb
			}
		}
	}

	if containerTechUsed {
		// create shared runtime
		assetsRunning := make([]string, 0)
		for _, deployTargetID := range macroState["deploy-targets"] {
			assetsRunning = append(assetsRunning, deployTargetID)
		}
		title := macroState["container-platform"][0] + " Runtime"
		sharedRuntime := model.InputSharedRuntime{
			ID:                       containerSharedRuntimeID,
			Description:              title,
			Tags:                     []string{model.NormalizeTag(macroState["container-platform"][0])},
			Technical_assets_running: assetsRunning,
		}
		*changeLogCollector = append(*changeLogCollector, "adding shared runtime: "+containerSharedRuntimeID)
		if !dryRun {
			if modelInput.Shared_runtimes == nil {
				modelInput.Shared_runtimes = make(map[string]model.InputSharedRuntime, 0)
			}
			modelInput.Shared_runtimes[title] = sharedRuntime
		}
	}

	return "Changeset valid", true, nil
}
