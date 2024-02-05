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

	cellStyles, err := createCellStyles(excel)
	if err != nil {
		return fmt.Errorf("unable to create cell styles: %w", err)
	}

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
					if err != nil {
						return fmt.Errorf("unable to set cell value: %w", err)
					}
				}
				err = excel.SetCellValue(sheetName, "S"+strconv.Itoa(excelRow), riskTracking.CheckedBy)
				if err != nil {
					return fmt.Errorf("unable to set cell value: %w", err)
				}
				err = excel.SetCellValue(sheetName, "T"+strconv.Itoa(excelRow), riskTracking.Ticket)
				if err != nil {
					return fmt.Errorf("unable to set cell value: %w", err)
				}
			}
			// styles
			leftCellsStyle, rightCellStyles := fromSeverityToExcelStyle(riskTrackingStatus, risk.Severity, cellStyles)
			err = setCellStyle(excel, sheetName, []setCellStyleCommand{
				{"A" + strconv.Itoa(excelRow), "F" + strconv.Itoa(excelRow), leftCellsStyle},
				{"G" + strconv.Itoa(excelRow), "I" + strconv.Itoa(excelRow), rightCellStyles},
				{"J" + strconv.Itoa(excelRow), "J" + strconv.Itoa(excelRow), cellStyles.blackRight},
				{"K" + strconv.Itoa(excelRow), "K" + strconv.Itoa(excelRow), cellStyles.blackSmall},
				{"L" + strconv.Itoa(excelRow), "L" + strconv.Itoa(excelRow), cellStyles.mitigation},
				{"M" + strconv.Itoa(excelRow), "M" + strconv.Itoa(excelRow), cellStyles.mitigation},
				{"N" + strconv.Itoa(excelRow), "N" + strconv.Itoa(excelRow), cellStyles.mitigation},
				{"O" + strconv.Itoa(excelRow), "O" + strconv.Itoa(excelRow), cellStyles.graySmall},
				{"P" + strconv.Itoa(excelRow), "P" + strconv.Itoa(excelRow), fromRiskTrackingToExcelStyle(riskTrackingStatus, cellStyles)},
				{"Q" + strconv.Itoa(excelRow), "Q" + strconv.Itoa(excelRow), cellStyles.blackSmall},
				{"R" + strconv.Itoa(excelRow), "R" + strconv.Itoa(excelRow), cellStyles.blackCenter},
				{"S" + strconv.Itoa(excelRow), "S" + strconv.Itoa(excelRow), cellStyles.blackCenter},
				{"T" + strconv.Itoa(excelRow), "T" + strconv.Itoa(excelRow), cellStyles.blackLeft},
			})
			if err != nil {
				return fmt.Errorf("unable to set cell style: %w", err)
			}
		}
	}

	err = excel.SetCellStyle(sheetName, "A1", "T1", cellStyles.headCenterBoldItalic)
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

type cellStyles struct {
	severityCriticalBold   int
	severityCriticalCenter int
	severityHighBold       int
	severityHighCenter     int
	severityElevatedBold   int
	severityElevatedCenter int
	severityMediumBold     int
	severityMediumCenter   int
	severityLowBold        int
	severityLowCenter      int
	redCenter              int
	greenCenter            int
	blueCenter             int
	yellowCenter           int
	orangeCenter           int
	grayCenter             int
	blackLeft              int
	blackLeftBold          int
	blackCenter            int
	blackRight             int
	blackSmall             int
	graySmall              int
	blackBold              int
	mitigation             int
	headCenter             int
	headCenterBoldItalic   int
	headCenterBold         int
}

func createCellStyles(excel *excelize.File) (*cellStyles, error) {
	styleSeverityCriticalBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorCriticalRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
	styleSeverityHighBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorHighRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
	styleSeverityElevatedBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorElevatedRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
	styleSeverityMediumBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorMediumRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
	styleSeverityLowBold, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorLowRisk(),
			Size:  12,
			Bold:  true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
	styleBlackSmall, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: "#000000",
			Size:  10,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
	styleGraySmall, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorOutOfScope(),
			Size:  10,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
	styleMitigation, err := excel.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: rgbHexColorRiskStatusMitigated(),
			Size:  10,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
	styleHeadCenterBoldItalic, err := excel.NewStyle(&excelize.Style{
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("unable to create style: %w", err)
	}

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
		return nil, fmt.Errorf("unable to set cell style: %w", err)
	}

	return &cellStyles{
		headCenter:             styleHeadCenter,
		headCenterBoldItalic:   styleHeadCenterBoldItalic,
		headCenterBold:         styleHeadCenterBold,
		severityCriticalBold:   styleSeverityCriticalBold,
		severityCriticalCenter: styleSeverityCriticalCenter,
		severityHighBold:       styleSeverityHighBold,
		severityHighCenter:     styleSeverityHighCenter,
		severityElevatedBold:   styleSeverityElevatedBold,
		severityElevatedCenter: styleSeverityElevatedCenter,
		severityMediumBold:     styleSeverityMediumBold,
		severityMediumCenter:   styleSeverityMediumCenter,
		severityLowBold:        styleSeverityLowBold,
		severityLowCenter:      styleSeverityLowCenter,
		redCenter:              styleRedCenter,
		greenCenter:            styleGreenCenter,
		blueCenter:             styleBlueCenter,
		yellowCenter:           styleYellowCenter,
		orangeCenter:           styleOrangeCenter,
		grayCenter:             styleGrayCenter,
		blackLeft:              styleBlackLeft,
		blackLeftBold:          styleBlackLeftBold,
		blackCenter:            styleBlackCenter,
		blackRight:             styleBlackRight,
		blackSmall:             styleBlackSmall,
		graySmall:              styleGraySmall,
		blackBold:              styleBlackBold,
		mitigation:             styleMitigation,
	}, nil
}

func fromRiskTrackingToExcelStyle(riskTrackingStatus types.RiskStatus, cellStyles *cellStyles) int {
	switch riskTrackingStatus {
	case types.Unchecked:
		return cellStyles.redCenter
	case types.Mitigated:
		return cellStyles.greenCenter
	case types.InProgress:
		return cellStyles.blueCenter
	case types.Accepted:
		return cellStyles.yellowCenter
	case types.InDiscussion:
		return cellStyles.orangeCenter
	case types.FalsePositive:
		return cellStyles.grayCenter
	default:
		return cellStyles.blackCenter
	}
}

func fromSeverityToExcelStyle(riskTrackingStatus types.RiskStatus, severity types.RiskSeverity, cellStyles *cellStyles) (int, int) {

	if riskTrackingStatus.IsStillAtRisk() {
		switch severity {
		case types.CriticalSeverity:
			return cellStyles.severityCriticalCenter, cellStyles.severityCriticalBold
		case types.HighSeverity:
			return cellStyles.severityHighCenter, cellStyles.severityHighBold
		case types.ElevatedSeverity:
			return cellStyles.severityElevatedCenter, cellStyles.severityElevatedBold
		case types.MediumSeverity:
			return cellStyles.severityMediumCenter, cellStyles.severityMediumBold
		case types.LowSeverity:
			return cellStyles.severityLowCenter, cellStyles.severityLowBold
		}
	}
	return cellStyles.blackCenter, cellStyles.blackBold
}

type setCellStyleCommand struct {
	hCell string
	vCell string
	Style int
}

func setCellStyle(excel *excelize.File, sheetName string, commands []setCellStyleCommand) error {
	for _, command := range commands {
		err := excel.SetCellStyle(sheetName, command.hCell, command.vCell, command.Style)
		if err != nil {
			return fmt.Errorf("unable to set cell style: %w", err)
		}
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

	cellStyles, err := createCellStyles(excel)
	if err != nil {
		return err
	}

	excelRow++ // as we have a header line
	if len(sortedTagsAvailable) > 0 {
		for _, techAsset := range sortedTechnicalAssetsByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, axis, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, techAsset.Title, techAsset.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
			for _, commLink := range techAsset.CommunicationLinksSorted() {
				err := writeRow(excel, &excelRow, sheetName, axis, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, commLink.Title, commLink.Tags)
				if err != nil {
					return fmt.Errorf("unable to write row: %w", err)
				}
			}
		}
		for _, dataAsset := range sortedDataAssetsByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, axis, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, dataAsset.Title, dataAsset.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
		for _, trustBoundary := range sortedTrustBoundariesByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, axis, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, trustBoundary.Title, trustBoundary.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
		for _, sharedRuntime := range sortedSharedRuntimesByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, axis, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, sharedRuntime.Title, sharedRuntime.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
	}

	err = excel.SetCellStyle(sheetName, "A1", "A1", cellStyles.headCenterBold)
	if len(sortedTagsAvailable) > 0 {
		err = excel.SetCellStyle(sheetName, "B1", axis+"1", cellStyles.headCenter)
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
	if err != nil {
		return fmt.Errorf("unable to write row: %w", err)
	}
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
