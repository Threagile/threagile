package types

import "strings"

const (
	MayContainSecrets                                 = "may_contain_secrets" // #nosec G101 // this is a constant for a string
	NoAuthenticationRequired                          = "no_authentication_required"
	IsHighValueTarget                                 = "high_value_target"
	IsWebService                                      = "web_service"
	IsIdentityStore                                   = "identity_store"
	IsNoNetworkSegmentationRequired                   = "no_network_segmentation_required"
	IsIdentityRelated                                 = "identity_related"
	IsFileStorage                                     = "file_storage"
	IsSearchRelated                                   = "search_related"
	IsVulnerableToQueryInjection                      = "vulnerable_to_query_injection"
	IsNoStorageAtRest                                 = "no_storage_at_rest"
	IsHTTPInternetAccessOK                            = "http_internet_access_ok"
	IsFTPInternetAccessOK                             = "ftp_internet_access_ok"
	IsSecurityControlRelated                          = "security_control_related"
	IsUnprotectedCommunicationsTolerated              = "unprotected_communications_tolerated"
	IsUnnecessaryDataTolerated                        = "unnecessary_data_tolerated"
	IsCloseToHighValueTargetsTolerated                = "close_to_high_value_targets_tolerated"
	IsClient                                          = "client"
	IsUsuallyAbleToPropagateIdentityToOutgoingTargets = "propagate_identity_to_outgoing_targets"
	IsLessProtectedType                               = "less_protected_type"
	IsUsuallyProcessingEndUserRequests                = "processing_end_user_requests"
	IsUsuallyStoringEndUserData                       = "storing_end_user_data"
	IsExclusivelyFrontendRelated                      = "frontend_related"
	IsExclusivelyBackendRelated                       = "backend_related"
	IsDevelopmentRelevant                             = "development_relevant"
	IsTrafficForwarding                               = "traffic_forwarding"
	IsEmbeddedComponent                               = "embedded_component"
)

type TechnologyList []*Technology

func (what TechnologyList) String() string {
	names := make([]string, len(what))
	for i, technology := range what {
		names[i] = technology.String()
	}

	return strings.Join(names, "/")
}

func (what TechnologyList) GetAttribute(firstAttribute string, otherAttributes ...string) bool {
	for _, attribute := range append(otherAttributes, firstAttribute) {
		for _, technology := range what {
			if technology.GetAttribute(attribute) {
				return true
			}
		}
	}

	return false
}

func (what TechnologyList) IsUnknown() bool {
	if what.GetAttribute(UnknownTechnology) {
		return true
	}

	for _, technology := range what {
		if len(technology.Attributes) > 0 {
			return false
		}
	}

	return true
}

func (what TechnologyList) HasAuthenticatingTechnology() bool {
	for _, technology := range what {
		t := *technology
		if t.IsAuthenticatingTechnology() {
			return true
		}
	}
	return false
}
