package add_vault

import (
	"fmt"
	"github.com/threagile/threagile/model"
	"sort"
	"strings"
)

func GetMacroDetails() model.MacroDetails {
	return model.MacroDetails{
		ID:          "add-vault",
		Title:       "Add Vault",
		Description: "This model macro adds a vault (secret storage) to the model.",
	}
}

var macroState = make(map[string][]string)
var questionsAnswered = make([]string, 0)
var withinTrustBoundary, createNewTrustBoundary bool

const createNewTrustBoundaryLabel = "CREATE NEW TRUST BOUNDARY"

var storageTypes = []string{
	"Cloud Provider (storage buckets or similar)",
	"Container Platform (orchestration platform managed storage)",
	"Database (SQL-DB, NoSQL-DB, object store or similar)", // TODO let user choose to reuse existing technical asset when shared storage (which would be bad)
	"Filesystem (local or remote)",
	"In-Memory (no persistent storage of secrets)",
	"Service Registry", // TODO let user choose which technical asset the registry is (for comm link)
}

var authenticationTypes = []string{
	"Certificate",
	"Cloud Provider (relying on cloud provider instance authentication)",
	"Container Platform (orchestration platform managed authentication)",
	"Credentials (username/password, API-key, secret token, etc.)",
}

func GetNextQuestion() (nextQuestion model.MacroQuestion, err error) {
	counter := len(questionsAnswered)
	if counter > 5 && !withinTrustBoundary {
		counter++
	}
	if counter > 6 && !createNewTrustBoundary {
		counter++
	}
	switch counter {
	case 0:
		return model.MacroQuestion{
			ID:              "vault-name",
			Title:           "What product is used as the vault?",
			Description:     "This name affects the technical asset's title and ID plus also the tags used.",
			PossibleAnswers: nil,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	case 1:
		return model.MacroQuestion{
			ID:              "storage-type",
			Title:           "What type of storage is used for the vault?",
			Description:     "This selection affects the type of technical asset for the persistence.",
			PossibleAnswers: storageTypes,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	case 2:
		return model.MacroQuestion{
			ID:              "authentication-type",
			Title:           "What type of authentication is used for accessing the vault?",
			Description:     "This selection affects the type of communication links.",
			PossibleAnswers: authenticationTypes,
			MultiSelect:     false,
			DefaultAnswer:   "",
		}, nil
	case 3:
		return model.MacroQuestion{
			ID:              "multi-tenant",
			Title:           "Is the vault used by multiple tenants?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "No",
		}, nil
	case 4:
		possibleAnswers := make([]string, 0)
		for id := range model.ParsedModelRoot.TechnicalAssets {
			possibleAnswers = append(possibleAnswers, id)
		}
		sort.Strings(possibleAnswers)
		if len(possibleAnswers) > 0 {
			return model.MacroQuestion{
				ID:              "clients",
				Title:           "Select all technical assets that make use of the vault and access it:",
				Description:     "This affects the communication links being generated.",
				PossibleAnswers: possibleAnswers,
				MultiSelect:     true,
				DefaultAnswer:   "",
			}, nil
		}
	case 5:
		return model.MacroQuestion{
			ID:              "within-trust-boundary",
			Title:           "Is the vault placed within a network trust boundary?",
			Description:     "",
			PossibleAnswers: []string{"Yes", "No"},
			MultiSelect:     false,
			DefaultAnswer:   "Yes",
		}, nil
	case 6:
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
	case 7:
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
	}
	return model.NoMoreQuestions(), nil
}

func ApplyAnswer(questionID string, answer ...string) (message string, validResult bool, err error) {
	macroState[questionID] = answer
	questionsAnswered = append(questionsAnswered, questionID)
	if questionID == "within-trust-boundary" {
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
	model.AddTagToModelInput(modelInput, macroState["vault-name"][0], dryRun, changeLogCollector)

	var serverSideTechAssets = make([]string, 0)

	if _, exists := model.ParsedModelRoot.DataAssets["Configuration Secrets"]; !exists {
		dataAsset := model.InputDataAsset{
			ID:                     "configuration-secrets",
			Description:            "Configuration secrets (like credentials, keys, certificates, etc.) secured and managed by a vault",
			Usage:                  model.DevOps.String(),
			Tags:                   []string{},
			Origin:                 "",
			Owner:                  "",
			Quantity:               model.VeryFew.String(),
			Confidentiality:        model.StrictlyConfidential.String(),
			Integrity:              model.Critical.String(),
			Availability:           model.Critical.String(),
			JustificationCiaRating: "Configuration secrets are rated as being 'strictly-confidential'.",
		}
		*changeLogCollector = append(*changeLogCollector, "adding data asset: configuration-secrets")
		if !dryRun {
			modelInput.DataAssets["Configuration Secrets"] = dataAsset
		}
	}

	databaseUsed := macroState["storage-type"][0] == storageTypes[2]
	filesystemUsed := macroState["storage-type"][0] == storageTypes[3]
	inMemoryUsed := macroState["storage-type"][0] == storageTypes[4]

	storageID := "vault-storage"

	if databaseUsed || filesystemUsed {
		tech := model.FileServer.String() // TODO ask for local or remote and only local use execution-environment (and add separate tech type LocalFilesystem?)
		if databaseUsed {
			tech = model.Database.String()
		}
		if _, exists := model.ParsedModelRoot.TechnicalAssets[storageID]; !exists {
			serverSideTechAssets = append(serverSideTechAssets, storageID)
			techAsset := model.InputTechnicalAsset{
				ID:                      storageID,
				Description:             "Vault Storage",
				Type:                    model.Datastore.String(),
				Usage:                   model.DevOps.String(),
				UsedAsClientByHuman:     false,
				OutOfScope:              false,
				JustificationOutOfScope: "",
				Size:                    model.Component.String(),
				Technology:              tech,
				Tags:                    []string{}, // TODO: let user enter or too detailed for a wizard?
				Internet:                false,
				Machine:                 model.Virtual.String(),                    // TODO: let user enter or too detailed for a wizard?
				Encryption:              model.DataWithSymmetricSharedKey.String(), // can be assumed for a vault product as at least having some good encryption
				Owner:                   "",
				Confidentiality:         model.Confidential.String(),
				Integrity:               model.Critical.String(),
				Availability:            model.Critical.String(),
				JustificationCiaRating:  "Vault components are only rated as 'confidential' as vaults usually apply a trust barrier to encrypt all data-at-rest with a vault key.",
				MultiTenant:             strings.ToLower(macroState["multi-tenant"][0]) == "yes",
				Redundant:               false,
				CustomDevelopedParts:    false,
				DataAssetsProcessed:     nil,
				DataAssetsStored:        []string{"configuration-secrets"},
				DataFormatsAccepted:     nil,
				CommunicationLinks:      nil,
			}
			*changeLogCollector = append(*changeLogCollector, "adding technical asset: "+storageID)
			if !dryRun {
				modelInput.TechnicalAssets["Vault Storage"] = techAsset
			}
		}
	}

	vaultID := model.MakeID(macroState["vault-name"][0]) + "-vault"

	if _, exists := model.ParsedModelRoot.TechnicalAssets[vaultID]; !exists {
		serverSideTechAssets = append(serverSideTechAssets, vaultID)
		commLinks := make(map[string]model.InputCommunicationLink)

		if databaseUsed || filesystemUsed {
			accessLink := model.InputCommunicationLink{
				Target:                 storageID,
				Description:            "Vault Storage Access",
				Protocol:               model.LocalFileAccess.String(),
				Authentication:         model.Credentials.String(),
				Authorization:          model.TechnicalUser.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               false,
				Usage:                  model.DevOps.String(),
				DataAssetsSent:         []string{"configuration-secrets"},
				DataAssetsReceived:     []string{"configuration-secrets"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
			if databaseUsed {
				accessLink.Protocol = model.SqlAccessProtocol.String() // TODO ask if encrypted and ask if NoSQL? or to detailed for a wizard?
			}
			commLinks["Vault Storage Access"] = accessLink
		}

		authentication := model.NoneAuthentication.String()
		if macroState["authentication-type"][0] == authenticationTypes[0] {
			authentication = model.ClientCertificate.String()
		} else if macroState["authentication-type"][0] == authenticationTypes[1] {
			authentication = model.Externalized.String()
		} else if macroState["authentication-type"][0] == authenticationTypes[2] {
			authentication = model.Externalized.String()
		} else if macroState["authentication-type"][0] == authenticationTypes[3] {
			authentication = model.Credentials.String()
		}
		for _, clientID := range macroState["clients"] { // add a connection from each client
			clientAccessCommLink := model.InputCommunicationLink{
				Target:                 vaultID,
				Description:            "Vault Access Traffic (by " + clientID + ")",
				Protocol:               model.HTTPS.String(),
				Authentication:         authentication,
				Authorization:          model.TechnicalUser.String(),
				Tags:                   []string{},
				VPN:                    false,
				IpFiltered:             false,
				Readonly:               true,
				Usage:                  model.DevOps.String(),
				DataAssetsSent:         nil,
				DataAssetsReceived:     []string{"configuration-secrets"},
				DiagramTweakWeight:     0,
				DiagramTweakConstraint: false,
			}
			clientAssetTitle := model.ParsedModelRoot.TechnicalAssets[clientID].Title
			if !dryRun {
				client := modelInput.TechnicalAssets[clientAssetTitle]
				client.CommunicationLinks["Vault Access ("+clientID+")"] = clientAccessCommLink
				modelInput.TechnicalAssets[clientAssetTitle] = client
			}
			// don't forget to also add the "configuration-secrets" data asset as processed on the client
			assetsProcessed := make([]string, 0)
			if modelInput.TechnicalAssets[clientAssetTitle].DataAssetsProcessed != nil {
				for _, val := range modelInput.TechnicalAssets[clientAssetTitle].DataAssetsProcessed {
					assetsProcessed = append(assetsProcessed, fmt.Sprintf("%v", val))
				}
			}
			mergedArrays := make([]string, 0)
			for _, val := range assetsProcessed {
				mergedArrays = append(mergedArrays, fmt.Sprintf("%v", val))
			}
			mergedArrays = append(mergedArrays, "configuration-secrets")
			if !dryRun {
				x := modelInput.TechnicalAssets[clientAssetTitle]
				x.DataAssetsProcessed = mergedArrays
				modelInput.TechnicalAssets[clientAssetTitle] = x
			}
		}

		techAsset := model.InputTechnicalAsset{
			ID:                      vaultID,
			Description:             macroState["vault-name"][0] + " Vault",
			Type:                    model.Process.String(),
			Usage:                   model.DevOps.String(),
			UsedAsClientByHuman:     false,
			OutOfScope:              false,
			JustificationOutOfScope: "",
			Size:                    model.Service.String(),
			Technology:              model.Vault.String(),
			Tags:                    []string{model.NormalizeTag(macroState["vault-name"][0])},
			Internet:                false,
			Machine:                 model.Virtual.String(),
			Encryption:              model.Transparent.String(),
			Owner:                   "",
			Confidentiality:         model.StrictlyConfidential.String(),
			Integrity:               model.Critical.String(),
			Availability:            model.Critical.String(),
			JustificationCiaRating:  "Vault components are rated as 'strictly-confidential'.",
			MultiTenant:             strings.ToLower(macroState["multi-tenant"][0]) == "yes",
			Redundant:               false,
			CustomDevelopedParts:    false,
			DataAssetsProcessed:     []string{"configuration-secrets"},
			DataAssetsStored:        nil,
			DataFormatsAccepted:     nil,
			CommunicationLinks:      commLinks,
		}
		if inMemoryUsed {
			techAsset.DataAssetsStored = []string{"configuration-secrets"}
		}
		*changeLogCollector = append(*changeLogCollector, "adding technical asset (including communication links): "+vaultID)
		if !dryRun {
			modelInput.TechnicalAssets[macroState["vault-name"][0]+" Vault"] = techAsset
		}
	}

	vaultEnvID := "vault-environment"
	if filesystemUsed {
		title := "Vault Environment"
		trustBoundary := model.InputTrustBoundary{
			ID:                    vaultEnvID,
			Description:           "Vault Environment",
			Type:                  model.ExecutionEnvironment.String(),
			Tags:                  []string{},
			TechnicalAssetsInside: []string{vaultID, storageID},
			TrustBoundariesNested: nil,
		}
		*changeLogCollector = append(*changeLogCollector, "adding trust boundary: "+vaultEnvID)
		if !dryRun {
			modelInput.TrustBoundaries[title] = trustBoundary
		}
	}

	if withinTrustBoundary {
		if createNewTrustBoundary {
			trustBoundaryType := macroState["new-trust-boundary-type"][0]
			title := "Vault Network"
			trustBoundary := model.InputTrustBoundary{
				ID:          "vault-network",
				Description: "Vault Network",
				Type:        trustBoundaryType,
				Tags:        []string{},
			}
			if filesystemUsed {
				trustBoundary.TrustBoundariesNested = []string{vaultEnvID}
			} else {
				trustBoundary.TechnicalAssetsInside = serverSideTechAssets
			}
			*changeLogCollector = append(*changeLogCollector, "adding trust boundary: vault-network")
			if !dryRun {
				modelInput.TrustBoundaries[title] = trustBoundary
			}
		} else { // adding to existing trust boundary
			existingTrustBoundaryToAddTo := macroState["selected-trust-boundary"][0]
			title := model.ParsedModelRoot.TrustBoundaries[existingTrustBoundaryToAddTo].Title

			if filesystemUsed { // ---------------------- nest as execution-environment trust boundary ----------------------
				boundariesNested := make([]string, 0)
				if modelInput.TrustBoundaries[title].TrustBoundariesNested != nil {
					values := modelInput.TrustBoundaries[title].TrustBoundariesNested
					for _, val := range values {
						boundariesNested = append(boundariesNested, fmt.Sprintf("%v", val))
					}
				}
				mergedArrays := make([]string, 0)
				for _, val := range boundariesNested {
					mergedArrays = append(mergedArrays, fmt.Sprintf("%v", val))
				}
				mergedArrays = append(mergedArrays, vaultEnvID)
				*changeLogCollector = append(*changeLogCollector, "filling existing trust boundary: "+existingTrustBoundaryToAddTo)
				if !dryRun {
					tb := modelInput.TrustBoundaries[title]
					tb.TrustBoundariesNested = mergedArrays
					modelInput.TrustBoundaries[title] = tb
				}
			} else { // ---------------------- place assets inside directly ----------------------
				assetsInside := make([]string, 0)
				if modelInput.TrustBoundaries[title].TechnicalAssetsInside != nil {
					values := modelInput.TrustBoundaries[title].TechnicalAssetsInside
					for _, val := range values {
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
					tb := modelInput.TrustBoundaries[title]
					tb.TechnicalAssetsInside = mergedArrays
					modelInput.TrustBoundaries[title] = tb
				}
			}
		}
	}

	return "Changeset valid", true, nil
}
