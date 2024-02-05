package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/threagile/threagile/pkg/security/types"
	"github.com/xuri/excelize/v2"
)

func WriteRisksExcelToFile(parsedModel *types.ParsedModel, filename string) error {
	excelRow := 0
	excel := excelize.NewFile()
	sheetName := parsedModel.Title
	err := excel.SetDocProps(&excelize.DocProperties{
		Category:       "Threat Model Risks Summary",
		ContentStatus:  "Final",
		Creator:        parsedModel.Author.Name,
		Description:    sheetName + " via Threagile",
		Identifier:     "xlsx",
		Keywords:       "Threat Model",
		LastModifiedBy: parsedModel.Author.Name,
		Revision:       "0",
		Subject:        sheetName,
		Title:          sheetName,
		Language:       "en-US",
		Version:        "1.0.0",
	})
	if err != nil {
		return fmt.Errorf("unable to set doc properties: %w", err)
	}

	sheetIndex, _ := excel.NewSheet(sheetName)
	_ = excel.DeleteSheet("Sheet1")
	orientation := "landscape"
	size := 9
	err = excel.SetPageLayout(sheetName, &excelize.PageLayoutOptions{Orientation: &orientation, Size: &size}) // A4
	if err != nil {
		return fmt.Errorf("unable to set page layout: %w", err)
	}

	err = excel.SetHeaderFooter(sheetName, &excelize.HeaderFooterOptions{
		DifferentFirst:   false,
		DifferentOddEven: false,
		OddHeader:        "&R&P",
		OddFooter:        "&C&F",
		EvenHeader:       "&L&P",
		EvenFooter:       "&L&D&R&T",
		FirstHeader:      `&Threat Model &"-,` + parsedModel.Title + `"Bold&"-,Regular"Risks Summary+000A&D`,
	})
	if err != nil {
		return fmt.Errorf("unable to set header/footer: %w", err)
	}

	err = setCellValue(excel, sheetName, []setCellValueCommand{
		{"A1", "Severity"},
		{"B1", "Likelihood"},
		{"C1", "Impact"},
		{"D1", "STRIDE"},
		{"E1", "Function"},
		{"F1", "CWE"},
		{"G1", "Risk Category"},
		{"H1", "Technical Asset"},
		{"I1", "Communication Link"},
		{"J1", "RAA %"},
		{"K1", "Identified Risk"},
		{"L1", "Action"},
		{"M1", "Mitigation"},
		{"N1", "Check"},
		{"O1", "ID"},
		{"P1", "Status"},
		{"Q1", "Justification"},
		{"R1", "Date"},
		{"S1", "Checked by"},
		{"T1", "Ticket"},
	})
	if err != nil {
		return fmt.Errorf("unable to set cell value: %w", err)
	}

	err = setColumnWidth(excel, sheetName, []setColumnWidthCommand{
		{"A", 12},
		{"B", 15},
		{"C", 15},
		{"D", 22},
		{"E", 16},
		{"F", 12},
		{"G", 50},
		{"H", 50},
		{"I", 50},
		{"J", 10},
		{"K", 75},
		{"L", 45},
		{"M", 75},
		{"N", 50},
		{"O", 10},
		{"P", 18},
		{"Q", 75},
		{"R", 18},
		{"S", 20},
		{"T", 20},
	})
	if err != nil {
		return fmt.Errorf("unable to set column width: %w", err)
	}

	styleSeverityCriticalBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorCriticalRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	styleSeverityCriticalCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorCriticalRisk(),
			Size:  12,
		},
	})
	styleSeverityHighBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorHighRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	styleSeverityHighCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorHighRisk(),
			Size:  12,
		},
	})
	styleSeverityElevatedBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorElevatedRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	styleSeverityElevatedCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorElevatedRisk(),
			Size:  12,
		},
	})
	styleSeverityMediumBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorMediumRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	styleSeverityMediumCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorMediumRisk(),
			Size:  12,
		},
	})
	styleSeverityLowBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorLowRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	styleSeverityLowCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorLowRisk(),
			Size:  12,
		},
	})

	styleRedCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorLowRisk(),
			Size:  12,
		},
	})
	styleGreenCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorRiskStatusMitigated(),
			Size:  12,
		},
	})
	styleBlueCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorRiskStatusInProgress(),
			Size:  12,
		},
	})
	styleYellowCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorRiskStatusAccepted(),
			Size:  12,
		},
	})
	styleOrangeCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorRiskStatusInDiscussion(),
			Size:  12,
		},
	})
	styleGrayCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorRiskStatusFalsePositive(),
			Size:  12,
		},
	})
	styleBlackLeft, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "left",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  12,
		},
	})
	styleBlackCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  12,
		},
	})
	styleBlackRight, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "right",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  12,
		},
	})
	styleBlackSmall, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: "#000000",
			Size:  10,
		},
	})
	styleGraySmall, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorOutOfScope(),
			Size:  10,
		},
	})
	styleBlackBold, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "right",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  12,
			Bold:  true,
		},
	})
	styleMitigation, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorRiskStatusMitigated(),
			Size:  10,
		},
	})

	excelRow++ // as we have a header line
	for _, category := range types.SortedRiskCategories(parsedModel) {
		risks := types.SortedRisksOfCategory(parsedModel, category)
		for _, risk := range risks {
			excelRow++
			techAsset := parsedModel.TechnicalAssets[risk.MostRelevantTechnicalAssetId]
			commLink := parsedModel.CommunicationLinks[risk.MostRelevantCommunicationLinkId]
			riskTrackingStatus := risk.GetRiskTrackingStatusDefaultingUnchecked(parsedModel)
			// content
			err := setCellValue(excel, sheetName, []setCellValueCommand{
				{"A" + strconv.Itoa(excelRow), risk.Severity.Title()},
				{"B" + strconv.Itoa(excelRow), risk.ExploitationLikelihood.Title()},
				{"C" + strconv.Itoa(excelRow), risk.ExploitationImpact.Title()},
				{"D" + strconv.Itoa(excelRow), category.STRIDE.Title()},
				{"E" + strconv.Itoa(excelRow), category.Function.Title()},
				{"F" + strconv.Itoa(excelRow), "CWE-" + strconv.Itoa(category.CWE)},
				{"G" + strconv.Itoa(excelRow), category.Title},
				{"H" + strconv.Itoa(excelRow), techAsset.Title},
				{"I" + strconv.Itoa(excelRow), commLink.Title},
				{"K" + strconv.Itoa(excelRow), removeFormattingTags(risk.Title)},
				{"L" + strconv.Itoa(excelRow), category.Action},
				{"M" + strconv.Itoa(excelRow), category.Mitigation},
				{"N" + strconv.Itoa(excelRow), category.Check},
				{"O" + strconv.Itoa(excelRow), risk.SyntheticId},
				{"P" + strconv.Itoa(excelRow), riskTrackingStatus.Title()},
			})
			if err != nil {
				return err
			}

			err = excel.SetCellFloat(sheetName, "J"+strconv.Itoa(excelRow), techAsset.RAA, 0, 32)
			if err != nil {
				return fmt.Errorf("unable to set cell float: %w", err)
			}
			if riskTrackingStatus != types.Unchecked {
				riskTracking := risk.GetRiskTracking(parsedModel)
				err = excel.SetCellValue(sheetName, "Q"+strconv.Itoa(excelRow), riskTracking.Justification)
				if err != nil {
					return fmt.Errorf("unable to set cell value: %w", err)
				}
				if !riskTracking.Date.IsZero() {
					err = excel.SetCellValue(sheetName, "R"+strconv.Itoa(excelRow), riskTracking.Date.Format("2006-01-02"))
				}
				err = excel.SetCellValue(sheetName, "S"+strconv.Itoa(excelRow), riskTracking.CheckedBy)
				err = excel.SetCellValue(sheetName, "T"+strconv.Itoa(excelRow), riskTracking.Ticket)
			}
			// styles
			if riskTrackingStatus.IsStillAtRisk() {
				switch risk.Severity {
				case types.CriticalSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityCriticalCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityCriticalBold)
				case types.HighSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityHighCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityHighBold)
				case types.ElevatedSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityElevatedCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityElevatedBold)
				case types.MediumSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityMediumCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityMediumBold)
				case types.LowSeverity:
					err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleSeverityLowCenter)
					err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleSeverityLowBold)
				}
			} else {
				err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(excelRow), "F"+strconv.Itoa(excelRow), styleBlackCenter)
				err = excel.SetCellStyle(sheetName, "G"+strconv.Itoa(excelRow), "I"+strconv.Itoa(excelRow), styleBlackBold)
			}
			var styleFromRiskTracking int
			switch riskTrackingStatus {
			case types.Unchecked:
				styleFromRiskTracking = styleRedCenter
			case types.Mitigated:
				styleFromRiskTracking = styleGreenCenter
			case types.InProgress:
				styleFromRiskTracking = styleBlueCenter
			case types.Accepted:
				styleFromRiskTracking = styleYellowCenter
			case types.InDiscussion:
				styleFromRiskTracking = styleOrangeCenter
			case types.FalsePositive:
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
			if err != nil {
				return fmt.Errorf("unable to set cell style: %w", err)
			}
		}
	}

	//styleHead, err := excel.NewStyle(`{"font":{"bold":true,"italic":false,"size":14,"color":"#000000"},"fill":{"type":"pattern","color":["#eeeeee"],"pattern":1}}`)
	//styleHeadCenter, err := excel.NewStyle(`{"font":{"bold":true,"italic":false,"size":14,"color":"#000000"},"fill":{"type":"pattern","color":["#eeeeee"],"pattern":1},"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false}}`)
	styleHeadCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color:  "#000000",
			Bold:   true,
			Italic: false,
			Size:   14,
		},
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"#eeeeee"},
			Pattern: 1,
		},
	})

	err = excel.SetCellStyle(sheetName, "A1", "T1", styleHeadCenter)
	if err != nil {
		return fmt.Errorf("unable to set cell style: %w", err)
	}

	excel.SetActiveSheet(sheetIndex)
	err = excel.SaveAs(filename)
	if err != nil {
		return fmt.Errorf("unable to save excel file: %w", err)
	}
	return nil
}

func WriteTagsExcelToFile(parsedModel *types.ParsedModel, filename string) error { // TODO: eventually when len(sortedTagsAvailable) == 0 is: write a hint in the Excel that no tags are used
	excelRow := 0
	excel := excelize.NewFile()
	sheetName := parsedModel.Title
	err := excel.SetDocProps(&excelize.DocProperties{
		Category:       "Tag Matrix",
		ContentStatus:  "Final",
		Creator:        parsedModel.Author.Name,
		Description:    sheetName + " via Threagile",
		Identifier:     "xlsx",
		Keywords:       "Tag Matrix",
		LastModifiedBy: parsedModel.Author.Name,
		Revision:       "0",
		Subject:        sheetName,
		Title:          sheetName,
		Language:       "en-US",
		Version:        "1.0.0",
	})
	if err != nil {
		return err
	}

	sheetIndex, _ := excel.NewSheet(sheetName)
	_ = excel.DeleteSheet("Sheet1")
	orientation := "landscape"
	size := 9
	err = excel.SetPageLayout(sheetName, &excelize.PageLayoutOptions{Orientation: &orientation, Size: &size}) // A4
	if err != nil {
		return err
	}

	err = excel.SetHeaderFooter(sheetName, &excelize.HeaderFooterOptions{
		DifferentFirst:   false,
		DifferentOddEven: false,
		OddHeader:        "&R&P",
		OddFooter:        "&C&F",
		EvenHeader:       "&L&P",
		EvenFooter:       "&L&D&R&T",
		FirstHeader:      `&Tag Matrix &"-,` + parsedModel.Title + `"Bold&"-,Regular"Summary+000A&D`,
	})
	if err != nil {
		return err
	}

	err = excel.SetCellValue(sheetName, "A1", "Element") // TODO is "Element" the correct generic name when referencing assets, links, trust boundaries etc.? Eventually add separate column "type of element" like "technical asset" or "data asset"?
	if err != nil {
		return err
	}

	sortedTagsAvailable := parsedModel.TagsActuallyUsed()
	sort.Strings(sortedTagsAvailable)
	axis := ""
	for i, tag := range sortedTagsAvailable {
		axis = determineColumnLetter(i)
		err = excel.SetCellValue(sheetName, axis+"1", tag)
		if err != nil {
			return err
		}
	}

	err = excel.SetColWidth(sheetName, "A", "A", 60)
	if err != nil {
		return err
	}

	if len(sortedTagsAvailable) > 0 {
		err = excel.SetColWidth(sheetName, "B", axis, 35)
	}
	if err != nil {
		return err
	}

	// styleBlackCenter, err := excel.NewStyle(`{"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#000000","size":12}}`)
	styleBlackCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  12,
		},
	})
	// styleBlackLeftBold, err := excel.NewStyle(`{"alignment":{"horizontal":"left","shrink_to_fit":true,"wrap_text":false},"font":{"color":"#000000","size":12,"bold":true}}`)
	styleBlackLeftBold, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "left",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  12,
			Bold:  true,
		},
	})

	excelRow++ // as we have a header line
	if len(sortedTagsAvailable) > 0 {
		for _, techAsset := range sortedTechnicalAssetsByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, techAsset.Title, techAsset.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
			for _, commLink := range techAsset.CommunicationLinksSorted() {
				err := writeRow(excel, &excelRow, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, commLink.Title, commLink.Tags)
				if err != nil {
					return fmt.Errorf("unable to write row: %w", err)
				}
			}
		}
		for _, dataAsset := range sortedDataAssetsByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, dataAsset.Title, dataAsset.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
		for _, trustBoundary := range sortedTrustBoundariesByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, trustBoundary.Title, trustBoundary.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
		for _, sharedRuntime := range sortedSharedRuntimesByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, axis, styleBlackLeftBold, styleBlackCenter, sortedTagsAvailable, sharedRuntime.Title, sharedRuntime.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
	}

	// styleHeadCenter, err := excel.NewStyle(`{"font":{"bold":false,"italic":false,"size":14,"color":"#000000"},"fill":{"type":"pattern","color":["#eeeeee"],"pattern":1},"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false}}`)
	styleHeadCenter, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  14,
		},
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"#eeeeee"},
			Pattern: 1,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set cell style: %w", err)
	}
	// styleHeadCenterBold, err := excel.NewStyle(`{"font":{"bold":true,"italic":false,"size":14,"color":"#000000"},"fill":{"type":"pattern","color":["#eeeeee"],"pattern":1},"alignment":{"horizontal":"center","shrink_to_fit":true,"wrap_text":false}}`)
	styleHeadCenterBold, err := excel.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  14,
			Bold:  true,
		},
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"#eeeeee"},
			Pattern: 1,
		},
	})
	err = excel.SetCellStyle(sheetName, "A1", "A1", styleHeadCenterBold)
	if len(sortedTagsAvailable) > 0 {
		err = excel.SetCellStyle(sheetName, "B1", axis+"1", styleHeadCenter)
	}
	if err != nil {
		return fmt.Errorf("unable to set cell style: %w", err)
	}

	excel.SetActiveSheet(sheetIndex)
	err = excel.SaveAs(filename)
	if err != nil {
		return fmt.Errorf("unable to save excel file: %w", err)
	}
	return nil
}

func sortedTrustBoundariesByTitle(parsedModel *types.ParsedModel) []types.TrustBoundary {
	boundaries := make([]types.TrustBoundary, 0)
	for _, boundary := range parsedModel.TrustBoundaries {
		boundaries = append(boundaries, boundary)
	}
	sort.Sort(types.ByTrustBoundaryTitleSort(boundaries))
	return boundaries
}

func sortedDataAssetsByTitle(parsedModel *types.ParsedModel) []types.DataAsset {
	assets := make([]types.DataAsset, 0)
	for _, asset := range parsedModel.DataAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByDataAssetTitleSort(assets))
	return assets
}

func writeRow(excel *excelize.File, excelRow *int, sheetName string, axis string, styleBlackLeftBold int, styleBlackCenter int,
	sortedTags []string, assetTitle string, tagsUsed []string) error {
	*excelRow++
	err := excel.SetCellValue(sheetName, "A"+strconv.Itoa(*excelRow), assetTitle)
	if err != nil {
		return fmt.Errorf("unable to write row: %w", err)
	}
	for i, tag := range sortedTags {
		if contains(tagsUsed, tag) {
			err = excel.SetCellValue(sheetName, determineColumnLetter(i)+strconv.Itoa(*excelRow), "X")
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
	}
	err = excel.SetCellStyle(sheetName, "A"+strconv.Itoa(*excelRow), "A"+strconv.Itoa(*excelRow), styleBlackLeftBold)
	err = excel.SetCellStyle(sheetName, "B"+strconv.Itoa(*excelRow), axis+strconv.Itoa(*excelRow), styleBlackCenter)
	if err != nil {
		return fmt.Errorf("unable to write row: %w", err)
	}
	return nil
}

func determineColumnLetter(i int) string {
	alphabet := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"}
	// can only have 700 columns in Excel that way, but that should be more than usable anyway ;)... otherwise think about your model...
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

type setCellValueCommand struct {
	cell  string
	value interface{}
}

func setCellValue(excel *excelize.File, sheetName string, cmds []setCellValueCommand) error {
	for _, cmd := range cmds {
		err := excel.SetCellValue(sheetName, cmd.cell, cmd.value)
		if err != nil {
			return err
		}
	}
	return nil
}

type setColumnWidthCommand struct {
	column string
	width  float64
}

func setColumnWidth(excel *excelize.File, sheetName string, cmds []setColumnWidthCommand) error {
	for _, cmd := range cmds {
		err := excel.SetColWidth(sheetName, cmd.column, cmd.column, cmd.width)
		if err != nil {
			return err
		}
	}
	return nil
}
