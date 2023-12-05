package main

import (
	"github.com/threagile/threagile/model"
	"sort"
)

// used from plugin caller:
func CalculateRAA() string {
	for techAssetID, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		aa := calculateAttackerAttractiveness(techAsset)
		aa += calculatePivotingNeighbourEffectAdjustment(techAsset)
		techAsset.RAA = calculateRelativeAttackerAttractiveness(aa)
		model.ParsedModelRoot.TechnicalAssets[techAssetID] = techAsset
	}
	// return intro text (for reporting etc., can be short summary-like)
	return "For each technical asset the <b>\"Relative Attacker Attractiveness\"</b> (RAA) value was calculated " +
		"in percent. The higher the RAA, the more interesting it is for an attacker to compromise the asset. The calculation algorithm takes " +
		"the sensitivity ratings and quantities of stored and processed data into account as well as the communication links of the " +
		"technical asset. Neighbouring assets to high-value RAA targets might receive an increase in their RAA value when they have " +
		"a communication link towards that target (\"Pivoting-Factor\").<br><br>The following lists all technical assets sorted by their " +
		"RAA value from highest (most attacker attractive) to lowest. This list can be used to prioritize on efforts relevant for the most " +
		"attacker-attractive technical assets:"
}

var attackerAttractivenessMinimum, attackerAttractivenessMaximum, spread float64 = 0, 0, 0

// set the concrete value in relation to the minimum and maximum of all
func calculateRelativeAttackerAttractiveness(attractiveness float64) float64 {
	if attackerAttractivenessMinimum == 0 || attackerAttractivenessMaximum == 0 {
		attackerAttractivenessMinimum, attackerAttractivenessMaximum = 9223372036854775807, -9223372036854775808
		// determine (only one time required) the min/max of all
		// first create them in memory (see the link replacement below for nested trust boundaries) - otherwise in Go ranging over map is random order
		// range over them in sorted (hence re-producible) way:
		keys := make([]string, 0)
		for k, _ := range model.ParsedModelRoot.TechnicalAssets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			techAsset := model.ParsedModelRoot.TechnicalAssets[key]
			if calculateAttackerAttractiveness(techAsset) > attackerAttractivenessMaximum {
				attackerAttractivenessMaximum = calculateAttackerAttractiveness(techAsset)
			}
			if calculateAttackerAttractiveness(techAsset) < attackerAttractivenessMinimum {
				attackerAttractivenessMinimum = calculateAttackerAttractiveness(techAsset)
			}
		}
		if !(attackerAttractivenessMinimum < attackerAttractivenessMaximum) {
			attackerAttractivenessMaximum = attackerAttractivenessMinimum + 1
		}
		spread = attackerAttractivenessMaximum - attackerAttractivenessMinimum
	}
	// calculate the percent value of the value within the defined min/max range
	value := attractiveness - attackerAttractivenessMinimum
	percent := float64(value) / float64(spread) * 100
	if percent <= 0 {
		percent = 1 // since 0 suggests no attacks at all
	}
	return percent
}

// increase the RAA (relative attacker attractiveness) by one third (1/3) of the delta to the highest outgoing neighbour (if positive delta)
func calculatePivotingNeighbourEffectAdjustment(techAsset model.TechnicalAsset) float64 {
	if techAsset.OutOfScope {
		return 0
	}
	adjustment := 0.0
	for _, commLink := range techAsset.CommunicationLinks {
		outgoingNeighbour := model.ParsedModelRoot.TechnicalAssets[commLink.TargetId]
		//if outgoingNeighbour.getTrustBoundary() == techAsset.getTrustBoundary() { // same trust boundary
		delta := calculateRelativeAttackerAttractiveness(calculateAttackerAttractiveness(outgoingNeighbour)) - calculateRelativeAttackerAttractiveness(calculateAttackerAttractiveness(techAsset))
		if delta > 0 {
			potentialIncrease := delta / 3
			//fmt.Println("Positive delta from", techAsset.Id, "to", outgoingNeighbour.Id, "is", delta, "yields to pivoting eighbour effect of an incrase of", potentialIncrease)
			if potentialIncrease > adjustment {
				adjustment = potentialIncrease
			}
		}
		//}
	}
	return adjustment
}

// The sum of all CIAs of the asset itself (fibonacci scale) plus the sum of the comm-links' transferred CIAs
// Multiplied by the quantity values of the data asset for C and I (not A)
func calculateAttackerAttractiveness(techAsset model.TechnicalAsset) float64 {
	if techAsset.OutOfScope {
		return 0
	}
	var score = 0.0
	score += techAsset.Confidentiality.AttackerAttractivenessForAsset()
	score += techAsset.Integrity.AttackerAttractivenessForAsset()
	score += techAsset.Availability.AttackerAttractivenessForAsset()
	for _, dataAssetProcessed := range techAsset.DataAssetsProcessed {
		dataAsset := model.ParsedModelRoot.DataAssets[dataAssetProcessed]
		score += dataAsset.Confidentiality.AttackerAttractivenessForProcessedOrStoredData() * dataAsset.Quantity.QuantityFactor()
		score += dataAsset.Integrity.AttackerAttractivenessForProcessedOrStoredData() * dataAsset.Quantity.QuantityFactor()
		score += dataAsset.Availability.AttackerAttractivenessForProcessedOrStoredData()
	}
	for _, dataAssetStored := range techAsset.DataAssetsStored {
		dataAsset := model.ParsedModelRoot.DataAssets[dataAssetStored]
		score += dataAsset.Confidentiality.AttackerAttractivenessForProcessedOrStoredData() * dataAsset.Quantity.QuantityFactor()
		score += dataAsset.Integrity.AttackerAttractivenessForProcessedOrStoredData() * dataAsset.Quantity.QuantityFactor()
		score += dataAsset.Availability.AttackerAttractivenessForProcessedOrStoredData()
	}
	for _, dataFlow := range techAsset.CommunicationLinks {
		for _, dataAssetSent := range dataFlow.DataAssetsSent {
			dataAsset := model.ParsedModelRoot.DataAssets[dataAssetSent]
			score += dataAsset.Confidentiality.AttackerAttractivenessForInOutTransferredData() * dataAsset.Quantity.QuantityFactor()
			score += dataAsset.Integrity.AttackerAttractivenessForInOutTransferredData() * dataAsset.Quantity.QuantityFactor()
			score += dataAsset.Availability.AttackerAttractivenessForInOutTransferredData()
		}
		for _, dataAssetReceived := range dataFlow.DataAssetsReceived {
			dataAsset := model.ParsedModelRoot.DataAssets[dataAssetReceived]
			score += dataAsset.Confidentiality.AttackerAttractivenessForInOutTransferredData() * dataAsset.Quantity.QuantityFactor()
			score += dataAsset.Integrity.AttackerAttractivenessForInOutTransferredData() * dataAsset.Quantity.QuantityFactor()
			score += dataAsset.Availability.AttackerAttractivenessForInOutTransferredData()
		}
	}
	if techAsset.Technology == model.LoadBalancer || techAsset.Technology == model.ReverseProxy {
		score = score / 5.5
	}
	if techAsset.Technology == model.Monitoring {
		score = score / 5
	}
	if techAsset.Technology == model.ContainerPlatform {
		score = score * 5
	}
	if techAsset.Technology == model.Vault {
		score = score * 2
	}
	if techAsset.Technology == model.BuildPipeline || techAsset.Technology == model.SourcecodeRepository || techAsset.Technology == model.ArtifactRegistry {
		score = score * 2
	}
	if techAsset.Technology == model.IdentityProvider || techAsset.Technology == model.IdentityStoreDatabase || techAsset.Technology == model.IdentityStoreLDAP {
		score = score * 2.5
	} else if techAsset.Type == model.Datastore {
		score = score * 2
	}
	if techAsset.MultiTenant {
		score = score * 1.5
	}
	return score
}
