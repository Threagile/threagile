package types

import "strings"

type TechnologyList []*Technology

func (what TechnologyList) String() string {
	names := make([]string, len(what))
	for i, technology := range what {
		names[i] = technology.String()
	}

	return strings.Join(names, "/")
}

func (what TechnologyList) HasAnyType(firstKind TechnicalAssetTechnology, otherKinds ...TechnicalAssetTechnology) bool {
	for _, kind := range append(otherKinds, firstKind) {
		for _, technology := range what {
			if technology.Type() == kind {
				return true
			}
		}
	}

	return false
}

func (what TechnologyList) HasAllTypes(firstKind TechnicalAssetTechnology, otherKinds ...TechnicalAssetTechnology) bool {
	for _, kind := range append(otherKinds, firstKind) {
		if !what.HasType(kind) {
			return false
		}
	}

	return true
}

func (what TechnologyList) HasType(kind TechnicalAssetTechnology) bool {
	for _, technology := range what {
		if technology.Type() == kind {
			return true
		}
	}

	return false
}

func (what TechnologyList) IsNotOnlyType(kind TechnicalAssetTechnology) bool {
	for _, technology := range what {
		if technology.Type() != kind {
			return true
		}
	}

	return false
}

func (what TechnologyList) GetAttribute(name string) bool {
	for _, technology := range what {
		if technology.GetAttribute(name) {
			return true
		}
	}

	return false
}

func (what TechnologyList) IsWebApplication() bool {
	return what.GetAttribute("web_application")
}

func (what TechnologyList) IsWebService() bool {
	return what.GetAttribute("web_service")
}

func (what TechnologyList) IsIdentityRelated() bool {
	return what.GetAttribute("identity_related")
}

func (what TechnologyList) IsSecurityControlRelated() bool {
	return what.GetAttribute("security_control_related")
}

func (what TechnologyList) IsUnprotectedCommunicationsTolerated() bool {
	return what.GetAttribute("unprotected_communications_tolerated")
}

func (what TechnologyList) IsUnnecessaryDataTolerated() bool {
	return what.GetAttribute("unnecessary_data_tolerated")
}

func (what TechnologyList) IsCloseToHighValueTargetsTolerated() bool {
	return what.GetAttribute("close_to_high_value_targets_tolerated")
}

func (what TechnologyList) IsClient() bool {
	return what.GetAttribute("client")
}

func (what TechnologyList) IsUsuallyAbleToPropagateIdentityToOutgoingTargets() bool {
	return what.GetAttribute("propagate_identity_to_outgoing_targets")
}

func (what TechnologyList) IsLessProtectedType() bool {
	return what.GetAttribute("less_protected_type")
}

func (what TechnologyList) IsUsuallyProcessingEndUserRequests() bool {
	return what.GetAttribute("processing_end_user_requests")
}

func (what TechnologyList) IsUsuallyStoringEndUserData() bool {
	return what.GetAttribute("storing_end_user_data")
}

func (what TechnologyList) IsExclusivelyFrontendRelated() bool {
	return what.GetAttribute("frontend_related")
}

func (what TechnologyList) IsExclusivelyBackendRelated() bool {
	return what.GetAttribute("backend_related")
}

func (what TechnologyList) IsDevelopmentRelevant() bool {
	return what.GetAttribute("development_relevant")
}

func (what TechnologyList) IsTrafficForwarding() bool {
	return what.GetAttribute("traffic_forwarding")
}

func (what TechnologyList) IsEmbeddedComponent() bool {
	return what.GetAttribute("embedded_component")
}
