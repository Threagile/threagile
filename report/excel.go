package report

import (
	"github.com/threagile/threagile/colors"
	"github.com/threagile/threagile/model"
	"github.com/xuri/excelize/v2"
	"sort"
	"strconv"
	"strings"
)

var excelRow int

func WriteRisksExcelToFile(filename string) {
	excelRow = 0
	excel := excelize.NewFile()
	sheetName := model.ParsedModelRoot.Title
	err := excel.SetDocProps(&excelize.DocProperties{
		Category:       "Threat Model Risks Summary",
		ContentStatus:  "Final",
		Creator:        model.ParsedModelRoot.Author.Name,
		Description:    sheetName + " via Threagile",
		Identifier:     "xlsx",
		Keywords:       "Threat Model",
		LastModifiedBy: model.ParsedModelRoot.Author.Name,
		Revision:       "0",
		Subject:        sheetName,
		Title:          sheetName,
		Language:       "en-US",
		Version:        "1.0.0",
	})
	checkErr(err)

	sheetIndex := excel.NewSheet(sheetName)
	excel.DeleteSheet("Sheet1")
	err = excel.SetPageLayout(sheetName,
		excelize.PageLayoutOrientation(excelize.OrientationLandscape),
		excelize.PageLayoutPaperSize(9)) // A4
	checkErr(err)

	err = excel.SetHeaderFooter(sheetName, &excelize.FormatHeaderFooter{
		DifferentFirst:   false,
		DifferentOddEven: false,
		OddHeader:        "&R&P",
		OddFooter:        "&C&F",
		EvenHeader:       "&L&P",
		EvenFooter:       "&L&D&R&T",
		FirstHeader:      `&Threat Model &"-,` + model.ParsedModelRoot.Title + `"Bold&"-,Regular"Risks Summary+000A&D`,
	})
	checkErr(err)

	err = excel.SetCellValue(sheetName, "A1", "Severity")
	err = excel.SetCellValue(sheetName, "B1", "Likelihood")
	err = excel.SetCellValue(sheetName, "C1", "Impact")
	err = excel.SetCellValue(sheetName, "D1", "STRIDE")
	err = excel.SetCellValue(sheetName, "E1", "Function")
	err = excel.SetCellValue(sheetName, "F1", "CWE")
	err = excel.SetCellValue(sheetName, "G1", "Risk Category")
	err = excel.SetCellValue(sheetName, "H1", "Technical Asset")
	err = excel.SetCellValue(sheetName, "I1", "Communication Link")
	err = excel.SetCellValue(sheetName, "J1", "RAA %")
	err = excel.SetCellValue(sheetName, "K1", "Identified Risk")
	err = excel.SetCellValue(sheetName, "L1", "Action")
	err = excel.SetCellValue(sheetName, "M1", "Mitigation")
	err = excel.SetCellValue(sheetName, "N1", "Check")
	err = excel.SetCellValue(sheetName, "O1", "ID")
	err = excel.SetCellValue(sheetName, "P1", "Status")
	err = excel.SetCellValue(sheetName, "Q1", "Justification")
	err = excel.SetCellValue(sheetName, "R1", "Date")
	err = excel.SetCellValue(sheetName, "S1", "Checked by")
	err = excel.SetCellValue(sheetName, "T1", "Ticket")

	err = excel.SetColWidth(sheetName, "A", "A", 12)
	err = excel.SetColWidth(sheetName, "B", "B", 15)
	err = excel.SetColWidth(sheetName, "C", "C", 15)
	err = excel.SetColWidth(sheetName, "D", "D", 22)
	err = excel.SetColWidth(sheetName, "E", "E", 16)
	err = excel.SetColWidth(sheetName, "F", "F", 12)
	err = excel.SetColWidth(sheetName, "G", "G", 50)
	err = excel.SetColWidth(sheetName, "H", "H", 50)
	err = excel.SetColWidth(sheetName, "I", "I", 50)
	err = excel.SetColWidth(sheetName, "J", "J", 10)
	err = excel.SetColWidth(sheetName, "K", "K", 75)
	err = excel.SetColWidth(sheetName, "L", "L", 45)
	err = excel.SetColWidth(sheetName, "M", "M", 75)
	err = excel.SetColWidth(sheetName, "N", "N", 50)
	err = excel.SetColWidth(sheetName, "O", "O", 10)
	err = excel.SetColWidth(sheetName, "P", "P", 18)
	err = excel.SetColWidth(sheetName, "Q", "Q", 75)
	err = excel.SetColWidth(sheetName, "R", "R", 18)
	err = excel.SetColWidth(sheetName, "S", "S", 20)
	err = excel.SetColWidth(sheetName, "T", "T", 20)
	checkErr(err)

	styleSeverityCriticalBold, err := excel.NewStyle(`{"font":{"color":"` + colors.RgbHexColorCriticalRisk() + `","size":12,"bold":true}}`)
	styleSeverityCriticalCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"` + colors.RgbHexColorCriticalRisk() + `","size":12}}`)
	styleSeverityHighBold, err := excel.NewStyle(`{"font":{"color":"` + colors.RgbHexColorHighRisk() + `","size":12,"bold":true}}`)
	styleSeverityHighCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"` + colors.RgbHexColorHighRisk() + `","size":12}}`)
	styleSeverityElevatedBold, err := excel.NewStyle(`{"font":{"color":"` + colors.RgbHexColorElevatedRisk() + `","size":12,"bold":true}}`)
	styleSeverityElevatedCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"` + colors.RgbHexColorElevatedRisk() + `","size":12}}`)
	styleSeverityMediumBold, err := excel.NewStyle(`{"font":{"color":"` + colors.RgbHexColorMediumRisk() + `","size":12,"bold":true}}`)
	styleSeverityMediumCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"` + colors.RgbHexColorMediumRisk() + `","size":12}}`)
	styleSeverityLowBold, err := excel.NewStyle(`{"font":{"color":"` + colors.RgbHexColorLowRisk() + `","size":12,"bold":true}}`)
	styleSeverityLowCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"` + colors.RgbHexColorLowRisk() + `","size":12}}`)

	styleRedCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"` + colors.RgbHexColorRiskStatusUnchecked() + `","size":12}}`)
	styleGreenCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"` + colors.RgbHexColorRiskStatusMitigated() + `","size":12}}`)
	styleBlueCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#` + colors.RgbHexColorRiskStatusInProgress() + `","size":12}}`)
	styleYellowCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#` + colors.RgbHexColorRiskStatusAccepted() + `","size":12}}`)
	styleOrangeCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#` + colors.RgbHexColorRiskStatusInDiscussion() + `","size":12}}`)
	styleGrayCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#` + colors.RgbHexColorRiskStatusFalsePositive() + `","size":12}}`)
	styleBlackLeft, err := excel.NewStyle(`{"alignment":{"horizontal":"left","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#000000","size":12}}`)
	styleBlackCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#000000","size":12}}`)
	styleBlackRight, err := excel.NewStyle(`{"alignment":{"horizontal":"right","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#000000","size":12}}`)
	styleBlackSmall, err := excel.NewStyle(`{"font":{"color":"#000000","size":10}}`)
	styleGraySmall, err := excel.NewStyle(`{"font":{"color":"` + colors.RgbHexColorOutOfScope() + `","size":10}}`)
	styleBlackBold, err := excel.NewStyle(`{"alignment":{"horizontal":"left","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#000000","size":12,"bold":true}}`)
	styleMitigation, err := excel.NewStyle(`{"font":{"color":"` + colors.RgbHexColorRiskStatusMitigated() + `","size":10}}`)

	excelRow++ // as we have a header line
	for _, category := range model.SortedRiskCategories() {
		risks := model.SortedRisksOfCategory(category)
		for _, risk := range risks {
			excelRow++
			techAsset := model.ParsedModelRoot.TechnicalAssets[risk.MostRelevantTechnicalAssetId]
			commLink := model.CommunicationLinks[risk.MostRelevantCommunicationLinkId]
			riskTrackingStatus := risk.GetRiskTrackingStatusDefaultingUnchecked()
			// content
			err := excel.SetCellValue(sheetName, "A"+strconv.Itoa(excelRow), risk.Severity.Title())
			err = excel.SetCellValue(sheetName, "B"+strconv.Itoa(excelRow), risk.ExploitationLikelihood.Title())
			err = excel.SetCellValue(sheetName, "C"+strconv.Itoa(excelRow), risk.ExploitationImpact.Title())
			err = excel.SetCellValue(sheetName, "D"+strconv.Itoa(excelRow), risk.Category.STRIDE.Title())
			err = excel.SetCellValue(sheetName, "E"+strconv.Itoa(excelRow), risk.Category.Function.Title())
			err = excel.SetCellValue(sheetName, "F"+strconv.Itoa(excelRow), "CWE-"+strconv.Itoa(risk.Category.CWE))
			err = excel.SetCellValue(sheetName, "G"+strconv.Itoa(excelRow), risk.Category.Title)
			err = excel.SetCellValue(sheetName, "H"+strconv.Itoa(excelRow), techAsset.Title)
			err = excel.SetCellValue(sheetName, "I"+strconv.Itoa(excelRow), commLink.Title)
			err = excel.SetCellFloat(sheetName, "J"+strconv.Itoa(excelRow), techAsset.RAA, 0, 32)
			err = excel.SetCellValue(sheetName, "K"+strconv.Itoa(excelRow), removeFormattingTags(risk.Title))
			err = excel.SetCellValue(sheetName, "L"+strconv.Itoa(excelRow), risk.Category.Action)
			err = excel.SetCellValue(sheetName, "M"+strconv.Itoa(excelRow), risk.Category.Mitigation)
			err = excel.SetCellValue(sheetName, "N"+strconv.Itoa(excelRow), risk.Category.Check)
			err = excel.SetCellValue(sheetName, "O"+strconv.Itoa(excelRow), risk.SyntheticId)
			err = excel.SetCellValue(sheetName, "P"+strconv.Itoa(excelRow), riskTrackingStatus.Title())
			if riskTrackingStatus != model.Unchecked {
				riskTracking := risk.GetRiskTracking()
				err = excel.SetCellValue(sheetName, "Q"+strconv.Itoa(excelRow), riskTracking.Justification)
				if !riskTracking.Date.IsZero() {
					err = excel.SetCellValue(sheetName, "R"+strconv.Itoa(excelRow), riskTracking.Date.Format("2006-01-02"))
				}
				err = excel.SetCellValue(sheetName, "S"+strconv.Itoa(excelRow), riskTracking.CheckedBy)
				err = excel.SetCellValue(sheetName, "T"+strconv.Itoa(excelRow), riskTracking.Ticket)
			}
			// styles
			if riskTrackingStatus.IsStillAtRisk() {
				switch risk.Severity {
				case model.CriticalSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityCriticalCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityCriticalBold)
				case model.HighSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityHighCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityHighBold)
				case model.ElevatedSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityElevatedCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityElevatedBold)
				case model.MediumSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityMediumCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityMediumBold)
				case model.LowSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityLowCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityLowBold)
				}
			} else {
				err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleBlackCenter)
				err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleBlackBold)
			}
			styleFromRiskTracking := styleBlackCenter
			switch riskTrackingStatus {
			case model.Unchecked:
				styleFromRiskTracking = styleRedCenter
			case model.Mitigated:
				styleFromRiskTracking = styleGreenCenter
			case model.InProgress:
				styleFromRiskTracking = styleBlueCenter
			case model.Accepted:
				styleFromRiskTracking = styleYellowCenter
			case model.InDiscussion:
				styleFromRiskTracking = styleOrangeCenter
			case model.FalsePositive:
				styleFromRiskTracking = styleGrayCenter
			default:
				styleFromRiskTracking = styleBlackCenter
			}
			err = excel.SetCellStyle(sheetName, "J"+strconv.Itoa(excelRow), "J"+strconv.Itoa(excelRow), styleBlackRight)
			err = excel.SetCellStyle(sheetName, "K"+strconv.Itoa(excelRow), "K"+strconv.Itoa(excelRow), styleBlackSmall)
			err = excel.SetCellStyle(sheetName, "L"+strconv.Itoa(excelRow), "L"+strconv.Itoa(excelRow), styleMitigation)
			err = excel.SetCellStyle(sheetName, "M"+strconv.Itoa(excelRow), "M"+strconv.Itoa(excelRow), styleMitigation)
			err = excel.SetCellStyle(sheetName, "N"+strconv.Itoa(excelRow), "N"+strconv.Itoa(excelRow), styleMitigation)
			err = excel.SetCellStyle(sheetName, "O"+strconv.Itoa(excelRow), "O"+strconv.Itoa(excelRow), styleGraySmall)
			err = excel.SetCellStyle(sheetName, "P"+strconv.Itoa(excelRow), "P"+strconv.Itoa(excelRow), styleFromRiskTracking)
			err = excel.SetCellStyle(sheetName, "Q"+strconv.Itoa(excelRow), "Q"+strconv.Itoa(excelRow), styleBlackSmall)
			err = excel.SetCellStyle(sheetName, "R"+strconv.Itoa(excelRow), "R"+strconv.Itoa(excelRow), styleBlackCenter)
			err = excel.SetCellStyle(sheetName, "S"+strconv.Itoa(excelRow), "S"+strconv.Itoa(excelRow), styleBlackCenter)
			err = excel.SetCellStyle(sheetName, "T"+strconv.Itoa(excelRow), "T"+strconv.Itoa(excelRow), styleBlackLeft)
			checkErr(err)
		}
	}

	//styleHead, err := excel.NewStyle(`{"font":{"bold":true,"italic":false,"size":14,"color":"#000000"},"fill":{"type":"pattern","color":["#eeeeee"],"pattern":1}}`)
	styleHeadCenter, err := excel.NewStyle(`{"font":{"bold":true,"italic":false,"size":14,"color":"#000000"},"fill":{"type":"pattern","color":["#eeeeee"],"pattern":1},"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false}}`)
	err = excel.SetCellStyle(sheetName, "A1", "T1", styleHeadCenter)
	checkErr(err)

	excel.SetActiveSheet(sheetIndex)
	err = excel.SaveAs(filename)
	checkErr(err)
}

func WriteTagsExcelToFile(filename string) { // TODO: eventually when len(sortedTagsAvailable) == 0 is: write a hint in the execel that no tags are used
	excelRow = 0
	excel := excelize.NewFile()
	sheetName := model.ParsedModelRoot.Title
	err := excel.SetDocProps(&excelize.DocProperties{
		Category:       "Tag Matrix",
		ContentStatus:  "Final",
		Creator:        model.ParsedModelRoot.Author.Name,
		Description:    sheetName + " via Threagile",
		Identifier:     "xlsx",
		Keywords:       "Tag Matrix",
		LastModifiedBy: model.ParsedModelRoot.Author.Name,
		Revision:       "0",
		Subject:        sheetName,
		Title:          sheetName,
		Language:       "en-US",
		Version:        "1.0.0",
	})
	checkErr(err)

	sheetIndex := excel.NewSheet(sheetName)
	excel.DeleteSheet("Sheet1")
	err = excel.SetPageLayout(sheetName,
		excelize.PageLayoutOrientation(excelize.OrientationLandscape),
		excelize.PageLayoutPaperSize(9)) // A4
	checkErr(err)

	err = excel.SetHeaderFooter(sheetName, &excelize.FormatHeaderFooter{
		DifferentFirst:   false,
		DifferentOddEven: false,
		OddHeader:        "&R&P",
		OddFooter:        "&C&F",
		EvenHeader:       "&L&P",
		EvenFooter:       "&L&D&R&T",
		FirstHeader:      `&Tag Matrix &"-,` + model.ParsedModelRoot.Title + `"Bold&"-,Regular"Summary+000A&D`,
	})
	checkErr(err)

	err = excel.SetCellValue(sheetName, "A1", "Element") // TODO is "Element" the correct generic name when referencing assets, links, trust boudaries etc.? Eventually add separate column "type of element" like "technical asset" or "data asset"?
	sortedTagsAvailable := model.TagsActuallyUsed()
	sort.Strings(sortedTagsAvailable)
	axis := ""
	for i, tag := range sortedTagsAvailable {
		axis = determineColumnLetter(i)
		err = excel.SetCellValue(sheetName, axis+"1", tag)
	}

	err = excel.SetColWidth(sheetName, "A", "A", 60)
	if len(sortedTagsAvailable) > 0 {
		err = excel.SetColWidth(sheetName, "B", axis, 35)
	}
	checkErr(err)

	styleBlackCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#000000","size":12}}`)
	styleBlackLeftBold, err := excel.NewStyle(`{"alignment":{"horizontal":"left","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#000000","size":12,"bold":true}}`)

	excelRow++ // as we have a header line
	if len(sortedTagsAvailable) > 0 {
		for _, techAsset := range model.SortedTechnicalAssetsByTitle() {
			writeRow(excel, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, techAsset.Title, techAsset.Tags)
			for _, commLink := range techAsset.CommunicationLinksSorted() {
				writeRow(excel, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, commLink.Title, commLink.Tags)
			}
		}
		for _, dataAsset := range model.SortedDataAssetsByTitle() {
			writeRow(excel, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, dataAsset.Title, dataAsset.Tags)
		}
		for _, trustBoundary := range model.SortedTrustBoundariesByTitle() {
			writeRow(excel, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, trustBoundary.Title, trustBoundary.Tags)
		}
		for _, sharedRuntime := range model.SortedSharedRuntimesByTitle() {
			writeRow(excel, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, sharedRuntime.Title, sharedRuntime.Tags)
		}
	}

	styleHeadCenter, err := excel.NewStyle(`{"font":{"bold":false,"italic":false,"size":14,"color":"#000000"},"fill":{"type":"pattern","color":["#eeeeee"],"pattern":1},"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false}}`)
	styleHeadCenterBold, err := excel.NewStyle(`{"font":{"bold":true,"italic":false,"size":14,"color":"#000000"},"fill":{"type":"pattern","color":["#eeeeee"],"pattern":1},"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false}}`)
	err = excel.SetCellStyle(sheetName, "A1", "A1", styleHeadCenterBold)
	if len(sortedTagsAvailable) > 0 {
		err = excel.SetCellStyle(sheetName, "B1", axis+"1", styleHeadCenter)
	}
	checkErr(err)

	excel.SetActiveSheet(sheetIndex)
	err = excel.SaveAs(filename)
	checkErr(err)
}

func writeRow(excel *excelize.File, sheetName string, axis string, styleBlackLeftBold int, styleBlackCenter int,
	sortedTags []string, assetTitle string, tagsUsed []string) {
	excelRow++
	err := excel.SetCellValue(sheetName, "A"+strconv.Itoa(excelRow), assetTitle)
	for i, tag := range sortedTags {
		if model.Contains(tagsUsed, tag) {
			err = excel.SetCellValue(sheetName, determineColumnLetter(i)+strconv.Itoa(excelRow), "X")
		}
	}
	err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "A"+strconv.Itoa(excelRow), styleBlackLeftBold)
	err = excel.SetCellStyle(sheetName, "B"+strconv.Itoa(excelRow), axis+strconv.Itoa(excelRow), styleBlackCenter)
	checkErr(err)
}

var alphabet = []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"}

func determineColumnLetter(i int) string {
	// can only have 700 columns in excel that way, but that should be more than usable anyway ;)... otherwise think about your model...
	i++
	if i < 26 {
		return alphabet[i]
	}
	return alphabet[(i/26)-1] + alphabet[i%26]
}

func removeFormattingTags(content string) interface{} {
	result := strings.ReplaceAll(strings.ReplaceAll(content, "<b>", ""), "</b>", "")
	result = strings.ReplaceAll(strings.ReplaceAll(result, "<i>", ""), "</i>", "")
	result = strings.ReplaceAll(strings.ReplaceAll(result, "<u>", ""), "</u>", "")
	return result
}
