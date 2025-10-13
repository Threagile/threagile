package types

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type PINameType int

const (
	DataAssetType PINameType = iota
	Biometrics
	BrowsingHistory
	BusinessCreatedProfiles
	CitizenImmigrationStatus
	DriverLicenseIInfo
	EmailAddress
	EmploymentData
	FinancialAccountCredentials
	GeneticData
	Geolocation
	IPAddress
	LocationData
	MessageContents
	Name
	OtherNonPI
	OtherPIDirectIdentifier
	OtherPIQuasiIdentifier
	PassportNumber
	PurchaseHistory
	RacialEthnicOrigin
	ReligiousPhilosophicalBeliefs
	SensitivePersonalInformation
	SexualOrientation
	SocialSecurity
	StateIDInfo
	UnionMembership
)

func PINameTypeValues() []TypeEnum {
	return []TypeEnum{
		DataAssetType, // Non-PI data asset
		Biometrics,
		BrowsingHistory,
		BusinessCreatedProfiles,
		CitizenImmigrationStatus,
		DriverLicenseIInfo,
		EmailAddress,
		EmploymentData,
		FinancialAccountCredentials,
		GeneticData,
		Geolocation,
		IPAddress,
		LocationData,
		MessageContents,
		Name,
		OtherNonPI, // Non-PI data asset
		OtherPIDirectIdentifier,
		OtherPIQuasiIdentifier,
		PassportNumber,
		PurchaseHistory,
		RacialEthnicOrigin,
		ReligiousPhilosophicalBeliefs,
		SensitivePersonalInformation,
		SexualOrientation,
		SocialSecurity,
		StateIDInfo,
		UnionMembership,
	}
}

var PINameTypeDescription = [...]TypeDescription{

	{"data-asset", "Non-PI data asset"},
	{"biometrics", "Biometrics, like facial recognition"},
	{"browsing-history", "Browsing history"},
	{"business-created-profiles", "Profiles businesses create about you, including pseudonymous profiles (“user1234”)"},
	{"citizen-immigration-status", "citizen or immigration status"},
	{"driver-license-info", "Driver’s license"},
	{"email-address", "Email address"},
	{"employment-data", "Employment data"},
	{"financial-account-credentials", "Financial account credentials"},
	{"genetic-data", "Genetic data"},
	{"geolocation", "A consumer’s precise geolocation"},
	{"ip-address", "IP address"},
	{"location-data", "Location data"},
	{"message-contents", "Contents of messages (e.g., emails, texts, chats), unless it’s directed to the business"},
	{"name", "Name or nickname"},
	{"other-non-pi", "Other data assets that are non-PI"},
	{"other-pi-direct-identifier", "Other data assets that are PI and direct identifiers"},
	{"other-pi-quasi-identifier", "Other data assets that are PI and quasi-identifiers"},
	{"passport-number", "Passport number"},
	{"purchase-history", "Purchase history"},
	{"racial-ethnic-origin", "Racial or ethnic origin"},
	{"religious-philosophical-beliefs", "religious or philosophical beliefs"},
	{"sensitive-personal-information", "Sensitive personal information"},
	{"sexual-orientation", "Information concerning your health, sex life, or sexual orientation"},
	{"social-security", "Social security"},
	{"state-id-info", "State ID"},
	{"union-membership", "union membership"},
}

func (what PINameType) String() string {
	return PINameTypeDescription[what].Name
}

func (what PINameType) Explain() string {
	return PINameTypeDescription[what].Description
}

func (what PINameType) Find(value string) (PINameType, error) {
	for index, description := range PINameTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return PINameType(index), nil
		}
	}

	return PINameType(0), fmt.Errorf("unknown pinametype value %q", value)
}

func ParsePINameType(value string) (PIName PINameType, err error) {
	return PINameType(0).Find(value)
}

func (what PINameType) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *PINameType) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.Find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what PINameType) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *PINameType) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.Find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

// Instead of PI Name strings in this map, it might be slightly better to use the PINameType enum as
// comparison is faster and more reliable.
// Moreover, if the PI Name is changed, we just need to change it at one place PINameTypeDescription,
// and it will be reflected everywhere due use of corresponding enums.
var DISet = map[PINameType]bool{
	Biometrics:                   true,
	BrowsingHistory:              true,
	BusinessCreatedProfiles:      true,
	DriverLicenseIInfo:           true,
	EmailAddress:                 true,
	EmploymentData:               true,
	FinancialAccountCredentials:  true,
	GeneticData:                  true,
	Geolocation:                  true,
	IPAddress:                    true,
	LocationData:                 true,
	MessageContents:              true,
	Name:                         true,
	OtherPIDirectIdentifier:      true,
	PassportNumber:               true,
	SensitivePersonalInformation: true,
	SexualOrientation:            true,
	SocialSecurity:               true,
}

var QDISet = map[PINameType]bool{
	CitizenImmigrationStatus:      true,
	OtherPIQuasiIdentifier:        true,
	RacialEthnicOrigin:            true,
	ReligiousPhilosophicalBeliefs: true,
	UnionMembership:               true,
}

func (what PINameType) IsDI() bool {
	return DISet[what]
}

func (what PINameType) IsQDI() bool {
	return QDISet[what]
}

/*
setDA: set of data asset IDs to be checked for quasi-identifiers
modelDataAssets: Map of all data asset IDs to data asset objects occuring in the input model
*/
func GetQuasiIDs(setDA []string, modelDataAssets map[string]*DataAsset) []string {
	listQDIs := []string{}
	for _, daID := range setDA {
		daObj := modelDataAssets[daID]
		if daObj.PINameType.IsQDI() {
			listQDIs = append(listQDIs, daObj.Id)
		}
	}
	return listQDIs
}

/*
setDA: set of data asset IDs to be checked for direct identifiers
modelDataAssets: Map of all data asset IDs to data asset objects occuring in the input model
*/
func GetDISet(setDA []string, modelDataAssets map[string]*DataAsset) []string {
	listDIs := []string{}
	for _, daID := range setDA {
		daObj := modelDataAssets[daID]
		if daObj.PINameType.IsDI() {
			listDIs = append(listDIs, daObj.Id)
		}
	}
	return listDIs
}

var PISet = map[PINameType]bool{
	Biometrics:                    true,
	BrowsingHistory:               true,
	BusinessCreatedProfiles:       true,
	CitizenImmigrationStatus:      true,
	DriverLicenseIInfo:            true,
	EmailAddress:                  true,
	EmploymentData:                true,
	FinancialAccountCredentials:   true,
	GeneticData:                   true,
	Geolocation:                   true,
	IPAddress:                     true,
	LocationData:                  true,
	MessageContents:               true,
	Name:                          true,
	OtherPIDirectIdentifier:       true,
	OtherPIQuasiIdentifier:        true,
	PassportNumber:                true,
	RacialEthnicOrigin:            true,
	ReligiousPhilosophicalBeliefs: true,
	SensitivePersonalInformation:  true,
	SexualOrientation:             true,
	SocialSecurity:                true,
	UnionMembership:               true,
}

func (what PINameType) IsPI() bool {
	return PISet[what]
}

func HasPI(setDA []string, modelDataAssets map[string]*DataAsset) bool {
	for _, daID := range setDA {
		daObj := modelDataAssets[daID]
		if daObj.PINameType.IsPI() {
			return true
		}
	}
	return false
}

/*
setDA: set of data asset IDs to be checked for PI
modelDataAssets: Map of all data asset IDs to data asset objects occuring in the input model
*/
func GetPIObjs(setDA []*DataAsset) []string {
	listDAIDs := make([]string, 0)
	for _, daObj := range setDA {
		if daObj.PINameType.IsPI() {
			listDAIDs = append(listDAIDs, daObj.Id)
		}
	}
	return listDAIDs
}

func addDAToMap(m map[string]bool, daList []string) map[string]bool {
	for _, da := range daList {
		_, p := m[da]
		if !p {
			m[da] = true
		}
	}
	return m
}
