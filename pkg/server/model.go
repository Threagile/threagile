/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package server

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/threagile/threagile/pkg/docs"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/security/types"
	"golang.org/x/crypto/argon2"
)

// creates a sub-folder (named by a new UUID) inside the token folder
func (s *server) createNewModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	ok = s.checkObjectCreationThrottler(ginContext, "MODEL")
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	aUuid := uuid.New().String()
	err := os.Mkdir(folderNameForModel(folderNameOfKey, aUuid), 0700)
	if err != nil {
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create model",
		})
		return
	}

	aYaml := `title: New Threat Model
threagile_version: ` + docs.ThreagileVersion + `
author:
  name: ""
  homepage: ""
date:
business_overview:
  description: ""
  images: []
technical_overview:
  description: ""
  images: []
business_criticality: ""
management_summary_comment: ""
questions: {}
abuse_cases: {}
security_requirements: {}
tags_available: []
data_assets: {}
technical_assets: {}
trust_boundaries: {}
shared_runtimes: {}
individual_risk_categories: {}
risk_tracking: {}
diagram_tweak_nodesep: ""
diagram_tweak_ranksep: ""
diagram_tweak_edge_layout: ""
diagram_tweak_suppress_edge_labels: false
diagram_tweak_invisible_connections_between_assets: []
diagram_tweak_same_rank_assets: []`

	ok = s.writeModelYAML(ginContext, aYaml, key, folderNameForModel(folderNameOfKey, aUuid), "New Model Creation", true)
	if ok {
		ginContext.JSON(http.StatusCreated, gin.H{
			"message": "model created",
			"id":      aUuid,
		})
	}
}

type payloadModels struct {
	ID                string    `yaml:"id" json:"id"`
	Title             string    `yaml:"title" json:"title"`
	TimestampCreated  time.Time `yaml:"timestamp_created" json:"timestamp_created"`
	TimestampModified time.Time `yaml:"timestamp_modified" json:"timestamp_modified"`
}

func (s *server) listModels(ginContext *gin.Context) { // TODO currently returns error when any model is no longer valid in syntax, so eventually have some fallback to not just bark on an invalid model...
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	result := make([]payloadModels, 0)
	modelFolders, err := os.ReadDir(folderNameOfKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	for _, dirEntry := range modelFolders {
		if dirEntry.IsDir() {
			modelStat, err := os.Stat(filepath.Join(folderNameOfKey, dirEntry.Name(), s.config.InputFile))
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusNotFound, gin.H{
					"error": "unable to list model",
				})
				return
			}
			aModel, _, ok := s.readModel(ginContext, dirEntry.Name(), key, folderNameOfKey)
			if !ok {
				return
			}
			fileInfo, err := dirEntry.Info()
			if err != nil {
				log.Println(err)
				ginContext.JSON(http.StatusNotFound, gin.H{
					"error": "unable to get file info",
				})
				return
			}
			result = append(result, payloadModels{
				ID:                dirEntry.Name(),
				Title:             aModel.Title,
				TimestampCreated:  fileInfo.ModTime(),
				TimestampModified: modelStat.ModTime(),
			})
		}
	}
	ginContext.JSON(http.StatusOK, result)
}

func (s *server) deleteModel(ginContext *gin.Context) {
	folderNameOfKey, _, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	folder, ok := s.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if ok {
		if folder != filepath.Clean(folder) {
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "model-id is weird",
			})
			return
		}
		err := os.RemoveAll(folder)
		if err != nil {
			ginContext.JSON(http.StatusNotFound, gin.H{
				"error": "model not found",
			})
			return
		}
		ginContext.JSON(http.StatusOK, gin.H{
			"message": "model deleted",
		})
	}
}

type payloadCover struct {
	Title  string       `yaml:"title" json:"title"`
	Date   time.Time    `yaml:"date" json:"date"`
	Author input.Author `yaml:"author" json:"author"`
}

func (s *server) setCover(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadCover{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.Title = payload.Title
		if !payload.Date.IsZero() {
			modelInput.Date = payload.Date.Format("2006-01-02")
		}
		modelInput.Author.Name = payload.Author.Name
		modelInput.Author.Homepage = payload.Author.Homepage
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Cover Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (s *server) getCover(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"title":  aModel.Title,
			"date":   aModel.Date,
			"author": aModel.Author,
		})
	}
}

type payloadOverview struct {
	ManagementSummaryComment string         `yaml:"management_summary_comment" json:"management_summary_comment"`
	BusinessCriticality      string         `yaml:"business_criticality" json:"business_criticality"`
	BusinessOverview         input.Overview `yaml:"business_overview" json:"business_overview"`
	TechnicalOverview        input.Overview `yaml:"technical_overview" json:"technical_overview"`
}

func (s *server) setOverview(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadOverview{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		criticality, err := types.ParseCriticality(payload.BusinessCriticality)
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		modelInput.ManagementSummaryComment = payload.ManagementSummaryComment
		modelInput.BusinessCriticality = criticality.String()
		modelInput.BusinessOverview.Description = payload.BusinessOverview.Description
		modelInput.BusinessOverview.Images = payload.BusinessOverview.Images
		modelInput.TechnicalOverview.Description = payload.TechnicalOverview.Description
		modelInput.TechnicalOverview.Images = payload.TechnicalOverview.Images
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Overview Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (s *server) getOverview(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, gin.H{
			"management_summary_comment": aModel.ManagementSummaryComment,
			"business_criticality":       aModel.BusinessCriticality,
			"business_overview":          aModel.BusinessOverview,
			"technical_overview":         aModel.TechnicalOverview,
		})
	}
}

type payloadAbuseCases map[string]string

func (s *server) setAbuseCases(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadAbuseCases{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.AbuseCases = payload
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Abuse Cases Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (s *server) getAbuseCases(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.AbuseCases)
	}
}

type payloadSecurityRequirements map[string]string

func (s *server) setSecurityRequirements(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSecurityRequirements{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		modelInput.SecurityRequirements = payload
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Security Requirements Update")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "model updated",
			})
		}
	}
}

func (s *server) getSecurityRequirements(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.SecurityRequirements)
	}
}

type payloadDataAsset struct {
	Title                  string   `yaml:"title" json:"title"`
	Id                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Usage                  string   `yaml:"usage" json:"usage"`
	Tags                   []string `yaml:"tags" json:"tags"`
	Origin                 string   `yaml:"origin" json:"origin"`
	Owner                  string   `yaml:"owner" json:"owner"`
	Quantity               string   `yaml:"quantity" json:"quantity"`
	Confidentiality        string   `yaml:"confidentiality" json:"confidentiality"`
	Integrity              string   `yaml:"integrity" json:"integrity"`
	Availability           string   `yaml:"availability" json:"availability"`
	JustificationCiaRating string   `yaml:"justification_cia_rating" json:"justification_cia_rating"`
}

func (s *server) getDataAssets(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.DataAssets)
	}
}

func (s *server) getDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				ginContext.JSON(http.StatusOK, gin.H{
					title: dataAsset,
				})
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func (s *server) deleteDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				// also remove all usages of this data asset !!
				for _, techAsset := range modelInput.TechnicalAssets {
					if techAsset.DataAssetsProcessed != nil {
						for i, parsedChangeCandidateAsset := range techAsset.DataAssetsProcessed {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.DataAssetsProcessed[i:], techAsset.DataAssetsProcessed[i+1:])                         // Shift a[i+1:] left one index.
								techAsset.DataAssetsProcessed[len(techAsset.DataAssetsProcessed)-1] = ""                             // Erase last element (write zero value).
								techAsset.DataAssetsProcessed = techAsset.DataAssetsProcessed[:len(techAsset.DataAssetsProcessed)-1] // Truncate slice.
							}
						}
					}
					if techAsset.DataAssetsStored != nil {
						for i, parsedChangeCandidateAsset := range techAsset.DataAssetsStored {
							referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
							if referencedAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								// Remove the element at index i
								// TODO needs more testing
								copy(techAsset.DataAssetsStored[i:], techAsset.DataAssetsStored[i+1:])                      // Shift a[i+1:] left one index.
								techAsset.DataAssetsStored[len(techAsset.DataAssetsStored)-1] = ""                          // Erase last element (write zero value).
								techAsset.DataAssetsStored = techAsset.DataAssetsStored[:len(techAsset.DataAssetsStored)-1] // Truncate slice.
							}
						}
					}
					if techAsset.CommunicationLinks != nil {
						for title, commLink := range techAsset.CommunicationLinks {
							for i, dataAssetSent := range commLink.DataAssetsSent {
								referencedAsset := fmt.Sprintf("%v", dataAssetSent)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.CommunicationLinks[title].DataAssetsSent[i:], techAsset.CommunicationLinks[title].DataAssetsSent[i+1:]) // Shift a[i+1:] left one index.
									techAsset.CommunicationLinks[title].DataAssetsSent[len(techAsset.CommunicationLinks[title].DataAssetsSent)-1] = ""     // Erase last element (write zero value).
									x := techAsset.CommunicationLinks[title]
									x.DataAssetsSent = techAsset.CommunicationLinks[title].DataAssetsSent[:len(techAsset.CommunicationLinks[title].DataAssetsSent)-1] // Truncate slice.
									techAsset.CommunicationLinks[title] = x
								}
							}
							for i, dataAssetReceived := range commLink.DataAssetsReceived {
								referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
								if referencedAsset == dataAsset.ID { // apply the removal
									referencesDeleted = true
									// Remove the element at index i
									// TODO needs more testing
									copy(techAsset.CommunicationLinks[title].DataAssetsReceived[i:], techAsset.CommunicationLinks[title].DataAssetsReceived[i+1:]) // Shift a[i+1:] left one index.
									techAsset.CommunicationLinks[title].DataAssetsReceived[len(techAsset.CommunicationLinks[title].DataAssetsReceived)-1] = ""     // Erase last element (write zero value).
									x := techAsset.CommunicationLinks[title]
									x.DataAssetsReceived = techAsset.CommunicationLinks[title].DataAssetsReceived[:len(techAsset.CommunicationLinks[title].DataAssetsReceived)-1] // Truncate slice.
									techAsset.CommunicationLinks[title] = x
								}
							}
						}
					}
				}
				for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
					if individualRiskCat.RisksIdentified != nil {
						for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
							if individualRiskInstance.MostRelevantDataAsset == dataAsset.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
								x.MostRelevantDataAsset = "" // TODO needs more testing
								modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.DataAssets, title)
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Deletion")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":            "data asset deleted",
						"id":                 dataAsset.ID,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func (s *server) setDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, dataAsset := range modelInput.DataAssets {
			if dataAsset.ID == ginContext.Param("data-asset-id") {
				payload := payloadDataAsset{}
				err := ginContext.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					ginContext.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
					return
				}
				dataAssetInput, ok := s.populateDataAsset(ginContext, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the asset from the map and re-insert it (with new key)
				delete(modelInput.DataAssets, title)
				modelInput.DataAssets[payload.Title] = dataAssetInput
				idChanged := dataAssetInput.ID != dataAsset.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					// also update all usages to point to the new (changed) ID !!
					for techAssetTitle, techAsset := range modelInput.TechnicalAssets {
						if techAsset.DataAssetsProcessed != nil {
							for i, parsedChangeCandidateAsset := range techAsset.DataAssetsProcessed {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.TechnicalAssets[techAssetTitle].DataAssetsProcessed[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.DataAssetsStored != nil {
							for i, parsedChangeCandidateAsset := range techAsset.DataAssetsStored {
								referencedAsset := fmt.Sprintf("%v", parsedChangeCandidateAsset)
								if referencedAsset == dataAsset.ID { // apply the ID change
									modelInput.TechnicalAssets[techAssetTitle].DataAssetsStored[i] = dataAssetInput.ID
								}
							}
						}
						if techAsset.CommunicationLinks != nil {
							for title, commLink := range techAsset.CommunicationLinks {
								for i, dataAssetSent := range commLink.DataAssetsSent {
									referencedAsset := fmt.Sprintf("%v", dataAssetSent)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsSent[i] = dataAssetInput.ID
									}
								}
								for i, dataAssetReceived := range commLink.DataAssetsReceived {
									referencedAsset := fmt.Sprintf("%v", dataAssetReceived)
									if referencedAsset == dataAsset.ID { // apply the ID change
										modelInput.TechnicalAssets[techAssetTitle].CommunicationLinks[title].DataAssetsReceived[i] = dataAssetInput.ID
									}
								}
							}
						}
					}
					for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
						if individualRiskCat.RisksIdentified != nil {
							for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
								if individualRiskInstance.MostRelevantDataAsset == dataAsset.ID { // apply the ID change
									x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
									x.MostRelevantDataAsset = dataAssetInput.ID // TODO needs more testing
									modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Update")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":    "data asset updated",
						"id":         dataAssetInput.ID,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "data asset not found",
		})
	}
}

func (s *server) createNewDataAsset(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadDataAsset{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.DataAssets[payload.Title]; exists {
			ginContext.JSON(http.StatusConflict, gin.H{
				"error": "data asset with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, asset := range modelInput.DataAssets {
			if asset.ID == payload.Id {
				ginContext.JSON(http.StatusConflict, gin.H{
					"error": "data asset with this id already exists",
				})
				return
			}
		}
		dataAssetInput, ok := s.populateDataAsset(ginContext, payload)
		if !ok {
			return
		}
		if modelInput.DataAssets == nil {
			modelInput.DataAssets = make(map[string]input.InputDataAsset)
		}
		modelInput.DataAssets[payload.Title] = dataAssetInput
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Data Asset Creation")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "data asset created",
				"id":      dataAssetInput.ID,
			})
		}
	}
}

func (s *server) populateDataAsset(ginContext *gin.Context, payload payloadDataAsset) (dataAssetInput input.InputDataAsset, ok bool) {
	usage, err := types.ParseUsage(payload.Usage)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	quantity, err := types.ParseQuantity(payload.Quantity)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	confidentiality, err := types.ParseConfidentiality(payload.Confidentiality)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	integrity, err := types.ParseCriticality(payload.Integrity)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	availability, err := types.ParseCriticality(payload.Availability)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return dataAssetInput, false
	}
	dataAssetInput = input.InputDataAsset{
		ID:                     payload.Id,
		Description:            payload.Description,
		Usage:                  usage.String(),
		Tags:                   lowerCaseAndTrim(payload.Tags),
		Origin:                 payload.Origin,
		Owner:                  payload.Owner,
		Quantity:               quantity.String(),
		Confidentiality:        confidentiality.String(),
		Integrity:              integrity.String(),
		Availability:           availability.String(),
		JustificationCiaRating: payload.JustificationCiaRating,
	}
	return dataAssetInput, true
}

func (s *server) getTrustBoundaries(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.TrustBoundaries)
	}
}

type payloadSharedRuntime struct {
	Title                  string   `yaml:"title" json:"title"`
	Id                     string   `yaml:"id" json:"id"`
	Description            string   `yaml:"description" json:"description"`
	Tags                   []string `yaml:"tags" json:"tags"`
	TechnicalAssetsRunning []string `yaml:"technical_assets_running" json:"technical_assets_running"`
}

func (s *server) setSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				payload := payloadSharedRuntime{}
				err := ginContext.BindJSON(&payload)
				if err != nil {
					log.Println(err)
					ginContext.JSON(http.StatusBadRequest, gin.H{
						"error": "unable to parse request payload",
					})
					return
				}
				sharedRuntimeInput, ok := populateSharedRuntime(ginContext, payload)
				if !ok {
					return
				}
				// in order to also update the title, remove the shared runtime from the map and re-insert it (with new key)
				delete(modelInput.SharedRuntimes, title)
				modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
				idChanged := sharedRuntimeInput.ID != sharedRuntime.ID
				if idChanged { // ID-CHANGE-PROPAGATION
					for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
						if individualRiskCat.RisksIdentified != nil {
							for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
								if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the ID change
									x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
									x.MostRelevantSharedRuntime = sharedRuntimeInput.ID // TODO needs more testing
									modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
								}
							}
						}
					}
				}
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Update")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":    "shared runtime updated",
						"id":         sharedRuntimeInput.ID,
						"id_changed": idChanged, // in order to signal to clients, that other model parts might've received updates as well and should be reloaded
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (s *server) getSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				ginContext.JSON(http.StatusOK, gin.H{
					title: sharedRuntime,
				})
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (s *server) createNewSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		payload := payloadSharedRuntime{}
		err := ginContext.BindJSON(&payload)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to parse request payload",
			})
			return
		}
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		if _, exists := modelInput.SharedRuntimes[payload.Title]; exists {
			ginContext.JSON(http.StatusConflict, gin.H{
				"error": "shared runtime with this title already exists",
			})
			return
		}
		// but later it will in memory keyed by its "id", so do this uniqueness check also
		for _, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == payload.Id {
				ginContext.JSON(http.StatusConflict, gin.H{
					"error": "shared runtime with this id already exists",
				})
				return
			}
		}
		if !checkTechnicalAssetsExisting(modelInput, payload.TechnicalAssetsRunning) {
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": "referenced technical asset does not exist",
			})
			return
		}
		sharedRuntimeInput, ok := populateSharedRuntime(ginContext, payload)
		if !ok {
			return
		}
		if modelInput.SharedRuntimes == nil {
			modelInput.SharedRuntimes = make(map[string]input.InputSharedRuntime)
		}
		modelInput.SharedRuntimes[payload.Title] = sharedRuntimeInput
		ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Creation")
		if ok {
			ginContext.JSON(http.StatusOK, gin.H{
				"message": "shared runtime created",
				"id":      sharedRuntimeInput.ID,
			})
		}
	}
}

func checkTechnicalAssetsExisting(modelInput input.ModelInput, techAssetIDs []string) (ok bool) {
	for _, techAssetID := range techAssetIDs {
		exists := false
		for _, val := range modelInput.TechnicalAssets {
			if val.ID == techAssetID {
				exists = true
				break
			}
		}
		if !exists {
			return false
		}
	}
	return true
}

func populateSharedRuntime(_ *gin.Context, payload payloadSharedRuntime) (sharedRuntimeInput input.InputSharedRuntime, ok bool) {
	sharedRuntimeInput = input.InputSharedRuntime{
		ID:                     payload.Id,
		Description:            payload.Description,
		Tags:                   lowerCaseAndTrim(payload.Tags),
		TechnicalAssetsRunning: payload.TechnicalAssetsRunning,
	}
	return sharedRuntimeInput, true
}

func (s *server) deleteSharedRuntime(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	modelInput, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		referencesDeleted := false
		// yes, here keyed by title in YAML for better readability in the YAML file itself
		for title, sharedRuntime := range modelInput.SharedRuntimes {
			if sharedRuntime.ID == ginContext.Param("shared-runtime-id") {
				// also remove all usages of this shared runtime !!
				for individualRiskCatTitle, individualRiskCat := range modelInput.IndividualRiskCategories {
					if individualRiskCat.RisksIdentified != nil {
						for individualRiskInstanceTitle, individualRiskInstance := range individualRiskCat.RisksIdentified {
							if individualRiskInstance.MostRelevantSharedRuntime == sharedRuntime.ID { // apply the removal
								referencesDeleted = true
								x := modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle]
								x.MostRelevantSharedRuntime = "" // TODO needs more testing
								modelInput.IndividualRiskCategories[individualRiskCatTitle].RisksIdentified[individualRiskInstanceTitle] = x
							}
						}
					}
				}
				// remove it itself
				delete(modelInput.SharedRuntimes, title)
				ok = s.writeModel(ginContext, key, folderNameOfKey, &modelInput, "Shared Runtime Deletion")
				if ok {
					ginContext.JSON(http.StatusOK, gin.H{
						"message":            "shared runtime deleted",
						"id":                 sharedRuntime.ID,
						"references_deleted": referencesDeleted, // in order to signal to clients, that other model parts might've been deleted as well
					})
				}
				return
			}
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "shared runtime not found",
		})
	}
}

func (s *server) getSharedRuntimes(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	aModel, _, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		ginContext.JSON(http.StatusOK, aModel.SharedRuntimes)
	}
}

func (s *server) readModel(ginContext *gin.Context, modelUUID string, key []byte, folderNameOfKey string) (modelInputResult input.ModelInput, yamlText string, ok bool) {
	modelFolder, ok := s.checkModelFolder(ginContext, modelUUID, folderNameOfKey)
	if !ok {
		return modelInputResult, yamlText, false
	}
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	fileBytes, err := os.ReadFile(filepath.Join(modelFolder, s.config.InputFile))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	nonce := fileBytes[0:12]
	ciphertext := fileBytes[12:]
	plaintext, err := aesGcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}

	r, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(r)
	modelInput := new(input.ModelInput).Defaults()
	yamlBytes := buf.Bytes()
	err = yaml.Unmarshal(yamlBytes, &modelInput)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to open model",
		})
		return modelInputResult, yamlText, false
	}
	return *modelInput, string(yamlBytes), true
}

func (s *server) writeModel(ginContext *gin.Context, key []byte, folderNameOfKey string, modelInput *input.ModelInput, changeReasonForHistory string) (ok bool) {
	modelFolder, ok := s.checkModelFolder(ginContext, ginContext.Param("model-id"), folderNameOfKey)
	if ok {
		modelInput.ThreagileVersion = docs.ThreagileVersion
		yamlBytes, err := yaml.Marshal(modelInput)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
		/*
			yamlBytes = model.ReformatYAML(yamlBytes)
		*/
		return s.writeModelYAML(ginContext, string(yamlBytes), key, modelFolder, changeReasonForHistory, false)
	}
	return false
}

func (s *server) checkModelFolder(ginContext *gin.Context, modelUUID string, folderNameOfKey string) (modelFolder string, ok bool) {
	uuidParsed, err := uuid.Parse(modelUUID)
	if err != nil {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	modelFolder = folderNameForModel(folderNameOfKey, uuidParsed.String())
	if _, err := os.Stat(modelFolder); os.IsNotExist(err) {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "model not found",
		})
		return modelFolder, false
	}
	return modelFolder, true
}

func (s *server) getModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)
	_, yamlText, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if ok {
		tmpResultFile, err := os.CreateTemp(s.config.TempFolder, "threagile-*.yaml")
		if err != nil {
			handleErrorInServiceCall(err, ginContext)
			return
		}
		err = os.WriteFile(tmpResultFile.Name(), []byte(yamlText), 0400)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to stream model file",
			})
			return
		}
		defer func() { _ = os.Remove(tmpResultFile.Name()) }()
		ginContext.FileAttachment(tmpResultFile.Name(), s.config.InputFile)
	}
}

// fully replaces threagile.yaml in sub-folder given by UUID
func (s *server) importModel(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer s.unlockFolder(folderNameOfKey)

	aUuid := ginContext.Param("model-id") // UUID is syntactically validated in readModel+checkModelFolder (next line) via uuid.Parse(modelUUID)
	_, _, ok = s.readModel(ginContext, aUuid, key, folderNameOfKey)
	if ok {
		// first analyze it simply by executing the full risk process (just discard the result) to ensure that everything would work
		yamlContent, ok := s.execute(ginContext, true)
		if ok {
			// if we're here, then no problem was raised, so ok to proceed
			ok = s.writeModelYAML(ginContext, string(yamlContent), key, folderNameForModel(folderNameOfKey, aUuid), "Model Import", false)
			if ok {
				ginContext.JSON(http.StatusCreated, gin.H{
					"message": "model imported",
				})
			}
		}
	}
}

func (s *server) analyzeModelOnServerDirectly(ginContext *gin.Context) {
	folderNameOfKey, key, ok := s.checkTokenToFolderName(ginContext)
	if !ok {
		return
	}
	s.lockFolder(folderNameOfKey)
	defer func() {
		s.unlockFolder(folderNameOfKey)
		var err error
		if r := recover(); r != nil {
			err = r.(error)
			if s.config.Verbose {
				log.Println(err)
			}
			log.Println(err)
			ginContext.JSON(http.StatusBadRequest, gin.H{
				"error": strings.TrimSpace(err.Error()),
			})
			ok = false
		}
	}()

	dpi, err := strconv.Atoi(ginContext.DefaultQuery("dpi", strconv.Itoa(s.config.GraphvizDPI)))
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}

	_, yamlText, ok := s.readModel(ginContext, ginContext.Param("model-id"), key, folderNameOfKey)
	if !ok {
		return
	}
	tmpModelFile, err := os.CreateTemp(s.config.TempFolder, "threagile-direct-analyze-*")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpModelFile.Name()) }()
	tmpOutputDir, err := os.MkdirTemp(s.config.TempFolder, "threagile-direct-analyze-")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.RemoveAll(tmpOutputDir) }()
	tmpResultFile, err := os.CreateTemp(s.config.TempFolder, "threagile-result-*.zip")
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	defer func() { _ = os.Remove(tmpResultFile.Name()) }()

	err = os.WriteFile(tmpModelFile.Name(), []byte(yamlText), 0400)

	s.doItViaRuntimeCall(tmpModelFile.Name(), tmpOutputDir, true, true, true, true, true, true, true, true, dpi)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	err = os.WriteFile(filepath.Join(tmpOutputDir, s.config.InputFile), []byte(yamlText), 0400)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}

	files := []string{
		filepath.Join(tmpOutputDir, s.config.InputFile),
		filepath.Join(tmpOutputDir, s.config.DataFlowDiagramFilenamePNG),
		filepath.Join(tmpOutputDir, s.config.DataAssetDiagramFilenamePNG),
		filepath.Join(tmpOutputDir, s.config.ReportFilename),
		filepath.Join(tmpOutputDir, s.config.ExcelRisksFilename),
		filepath.Join(tmpOutputDir, s.config.ExcelTagsFilename),
		filepath.Join(tmpOutputDir, s.config.JsonRisksFilename),
		filepath.Join(tmpOutputDir, s.config.JsonTechnicalAssetsFilename),
		filepath.Join(tmpOutputDir, s.config.JsonStatsFilename),
	}
	if s.config.KeepDiagramSourceFiles {
		files = append(files, filepath.Join(tmpOutputDir, s.config.DataFlowDiagramFilenameDOT))
		files = append(files, filepath.Join(tmpOutputDir, s.config.DataAssetDiagramFilenameDOT))
	}
	err = zipFiles(tmpResultFile.Name(), files)
	if err != nil {
		handleErrorInServiceCall(err, ginContext)
		return
	}
	if s.config.Verbose {
		fmt.Println("Streaming back result file: " + tmpResultFile.Name())
	}
	ginContext.FileAttachment(tmpResultFile.Name(), "threagile-result.zip")
}

func (s *server) writeModelYAML(ginContext *gin.Context, yaml string, key []byte, modelFolder string, changeReasonForHistory string, skipBackup bool) (ok bool) {
	if s.config.Verbose {
		fmt.Println("about to write " + strconv.Itoa(len(yaml)) + " bytes of yaml into model folder: " + modelFolder)
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(yaml))
	_ = w.Close()
	plaintext := b.Bytes()
	cryptoKey := generateKeyFromAlreadyStrongRandomInput(key)
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	ciphertext := aesGcm.Seal(nil, nonce, plaintext, nil)
	if !skipBackup {
		err = s.backupModelToHistory(modelFolder, changeReasonForHistory)
		if err != nil {
			log.Println(err)
			ginContext.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to write model",
			})
			return false
		}
	}
	f, err := os.Create(filepath.Join(modelFolder, s.config.InputFile))
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to write model",
		})
		return false
	}
	_, _ = f.Write(nonce)
	_, _ = f.Write(ciphertext)
	_ = f.Close()
	return true
}

func (s *server) lockFolder(folderName string) {
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	_, exists := s.locksByFolderName[folderName]
	if !exists {
		s.locksByFolderName[folderName] = &sync.Mutex{}
	}
	s.locksByFolderName[folderName].Lock()
}

func (s *server) unlockFolder(folderName string) {
	if _, exists := s.locksByFolderName[folderName]; exists {
		s.locksByFolderName[folderName].Unlock()
		delete(s.locksByFolderName, folderName)
	}
}

func (s *server) backupModelToHistory(modelFolder string, changeReasonForHistory string) (err error) {
	historyFolder := filepath.Join(modelFolder, "history")
	if _, err := os.Stat(historyFolder); os.IsNotExist(err) {
		err = os.Mkdir(historyFolder, 0700)
		if err != nil {
			return err
		}
	}
	inputModel, err := os.ReadFile(filepath.Join(modelFolder, s.config.InputFile))
	if err != nil {
		return err
	}
	historyFile := filepath.Join(historyFolder, time.Now().Format("2006-01-02 15:04:05")+" "+changeReasonForHistory+".backup")
	err = os.WriteFile(historyFile, inputModel, 0400)
	if err != nil {
		return err
	}
	// now delete any old files if over limit to keep
	files, err := os.ReadDir(historyFolder)
	if err != nil {
		return err
	}
	if len(files) > s.config.BackupHistoryFilesToKeep {
		requiredToDelete := len(files) - s.config.BackupHistoryFilesToKeep
		sort.Slice(files, func(i, j int) bool {
			return files[i].Name() < files[j].Name()
		})
		for _, file := range files {
			requiredToDelete--
			if file.Name() != filepath.Clean(file.Name()) {
				return fmt.Errorf("weird file name %v", file.Name())
			}
			err = os.Remove(filepath.Join(historyFolder, file.Name()))
			if err != nil {
				return err
			}
			if requiredToDelete <= 0 {
				break
			}
		}
	}
	return
}

func folderNameForModel(folderNameOfKey string, uuid string) string {
	return filepath.Join(folderNameOfKey, uuid)
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func generateKeyFromAlreadyStrongRandomInput(alreadyRandomInput []byte) []byte {
	// Establish the parameters to use for Argon2.
	p := &argon2Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   keySize,
	}
	// As the input is already cryptographically secure random, the salt is simply the first n bytes
	salt := alreadyRandomInput[0:p.saltLength]
	hash := argon2.IDKey(alreadyRandomInput[p.saltLength:], salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	return hash
}

func lowerCaseAndTrim(tags []string) []string {
	for i := range tags {
		tags[i] = strings.ToLower(strings.TrimSpace(tags[i]))
	}
	return tags
}
