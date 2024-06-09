package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/types"
	"github.com/xuri/excelize/v2"
)

func WriteRisksExcelToFile(parsedModel *types.Model, filename string, config reportConfigReader) error {
	columns := new(ExcelColumns).GetColumns()
	excel := excelize.NewFile()
	sheetName := parsedModel.Title

	setDocPropsError := excel.SetDocProps(&excelize.DocProperties{
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
	if setDocPropsError != nil {
		return fmt.Errorf("failed to set doc properties: %w", setDocPropsError)
	}

	sheetIndex, newSheetError := excel.NewSheet(sheetName)
	if newSheetError != nil {
		return fmt.Errorf("failed to add sheet: %w", newSheetError)
	}

	deleteSheetError := excel.DeleteSheet("Sheet1")
	if deleteSheetError != nil {
		return fmt.Errorf("failed to delete sheet: %w", deleteSheetError)
	}

	orientation := "landscape"
	size := 9 // A4
	setPageLayoutError := excel.SetPageLayout(sheetName, &excelize.PageLayoutOptions{Orientation: &orientation, Size: &size})
	if setPageLayoutError != nil {
		return fmt.Errorf("unable to set page layout: %w", setPageLayoutError)
	}

	setHeaderFooterError := excel.SetHeaderFooter(sheetName, &excelize.HeaderFooterOptions{
		DifferentFirst:   false,
		DifferentOddEven: false,
		OddHeader:        "&R&P",
		OddFooter:        "&C&F",
		EvenHeader:       "&L&P",
		EvenFooter:       "&L&D&R&T",
		FirstHeader:      `&Threat Model &"-,` + parsedModel.Title + `"Bold&"-,Regular"Risks Summary+000A&D`,
	})
	if setHeaderFooterError != nil {
		return fmt.Errorf("unable to set header/footer: %w", setHeaderFooterError)
	}

	// set header row
	for columnLetter, column := range columns {
		setCellValueError := excel.SetCellValue(sheetName, columnLetter+"1", column.Title)
		if setCellValueError != nil {
			return fmt.Errorf("unable to set cell value: %w", setCellValueError)
		}
	}

	cellStyles, createCellStylesError := new(ExcelStyles).Init(excel)
	if createCellStylesError != nil {
		return fmt.Errorf("unable to create cell styles: %w", createCellStylesError)
	}

	// get sorted risks
	riskItems := make([]RiskItem, 0)
	for _, category := range parsedModel.SortedRiskCategories() {
		risks := parsedModel.SortedRisksOfCategory(category)
		for _, risk := range risks {
			techAsset := parsedModel.TechnicalAssets[risk.MostRelevantTechnicalAssetId]
			techAssetTitle := ""
			techAssetRAA := 0.
			if techAsset != nil {
				techAssetTitle = techAsset.Title
				techAssetRAA = techAsset.RAA
			}

			commLink := parsedModel.CommunicationLinks[risk.MostRelevantCommunicationLinkId]
			commLinkTitle := ""
			if commLink != nil {
				commLinkTitle = commLink.Title
			}

			date := ""
			riskTracking := risk.GetRiskTrackingWithDefault(parsedModel)
			if !riskTracking.Date.IsZero() {
				date = riskTracking.Date.Format("2006-01-02")
			}

			riskItems = append(riskItems, RiskItem{
				Columns: []string{
					risk.Severity.Title(),
					risk.ExploitationLikelihood.Title(),
					risk.ExploitationImpact.Title(),
					category.STRIDE.Title(),
					category.Function.Title(),
					"CWE-" + strconv.Itoa(category.CWE),
					category.Title,
					techAssetTitle,
					commLinkTitle,
					decimal.NewFromFloat(techAssetRAA).StringFixed(0),
					removeFormattingTags(risk.Title),
					category.Action,
					category.Mitigation,
					category.Check,
					risk.SyntheticId,
					riskTracking.Status.Title(),
					riskTracking.Justification,
					date,
					riskTracking.CheckedBy,
					riskTracking.Ticket,
				},
				Status:   riskTracking.Status,
				Severity: risk.Severity,
			})
		}
	}

	// group risks
	groupedRisk, groupedRiskError := new(RiskGroup).Make(riskItems, columns, config.RiskExcelConfigSortByColumns())
	if groupedRiskError != nil {
		return fmt.Errorf("failed to group risks: %w", groupedRiskError)
	}

	// write data
	writeError := groupedRisk.Write(excel, sheetName, cellStyles)
	if writeError != nil {
		return fmt.Errorf("failed to write data: %w", writeError)
	}

	// set header style
	setCellStyleError := excel.SetCellStyle(sheetName, "A1", "T1", cellStyles.headCenterBoldItalic)
	if setCellStyleError != nil {
		return fmt.Errorf("unable to set cell style: %w", setCellStyleError)
	}

	// fix column width
	cols, colsError := excel.GetCols(sheetName)
	if colsError == nil {
		for colIndex, col := range cols {
			name, columnNumberToNameError := excelize.ColumnNumberToName(colIndex + 1)
			if columnNumberToNameError != nil {
				return columnNumberToNameError
			}

			var minWidth float64 = 0
			width, widthOk := config.RiskExcelConfigWidthOfColumns()[columns[name].Title]
			if widthOk {
				minWidth = width
			} else {
				var largestWidth float64 = 0
				for rowIndex, rowCell := range col {
					cellWidth := float64(utf8.RuneCountInString(rowCell) + 1) // + 1 for margin

					cellName, coordinateError := excelize.CoordinatesToCellName(colIndex+1, rowIndex+1)
					if coordinateError == nil {
						style, styleError := excel.GetCellStyle(sheetName, cellName)
						if styleError == nil {
							styleDetails, detailsError := excel.GetStyle(style)
							if detailsError == nil {
								if styleDetails.Font != nil && styleDetails.Font.Size > 0 {
									cellWidth *= styleDetails.Font.Size / 14.
								}
							}
						}
					}

					if cellWidth > largestWidth {
						largestWidth = cellWidth
					}
				}

				for columnLetter := range columns {
					if strings.EqualFold(columnLetter, name) {
						minWidth = columns[columnLetter].Width
					}
				}

				if largestWidth < 100 {
					minWidth = largestWidth
				}

				if minWidth < 8 {
					minWidth = 8
				}
			}

			setColWidthError := excel.SetColWidth(sheetName, name, name, minWidth)
			if setColWidthError != nil {
				return setColWidthError
			}
		}
	}

	// hide some columns
	for columnLetter, column := range columns {
		for _, hiddenColumn := range config.RiskExcelConfigHideColumns() {
			if strings.EqualFold(hiddenColumn, column.Title) {
				hideColumnError := excel.SetColVisible(sheetName, columnLetter, false)
				if hideColumnError != nil {
					return fmt.Errorf("unable to hide column: %w", hideColumnError)
				}
			}
		}
	}

	// freeze header
	freezeError := excel.SetPanes(sheetName, &excelize.Panes{
		Freeze:      true,
		Split:       false,
		XSplit:      0,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "bottomLeft",
	})
	if freezeError != nil {
		return fmt.Errorf("unable to freeze header: %w", freezeError)
	}

	excel.SetActiveSheet(sheetIndex)

	// save file
	saveAsError := excel.SaveAs(filename)
	if saveAsError != nil {
		return fmt.Errorf("unable to save excel file: %w", saveAsError)
	}

	return nil
}

func WriteTagsExcelToFile(parsedModel *types.Model, filename string) error { // TODO: eventually when len(sortedTagsAvailable) == 0 is: write a hint in the Excel that no tags are used
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
	for i, tag := range sortedTagsAvailable {
		cellName, coordinatesToCellNameError := excelize.CoordinatesToCellName(i+2, 1)
		if coordinatesToCellNameError != nil {
			return fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", i+2, 1, coordinatesToCellNameError)
		}

		err = excel.SetCellValue(sheetName, cellName, tag)
		if err != nil {
			return err
		}
	}

	err = excel.SetColWidth(sheetName, "A", "A", 60)
	if err != nil {
		return err
	}

	lastColumn, _ := excelize.ColumnNumberToName(len(sortedTagsAvailable) + 2)
	if len(sortedTagsAvailable) > 0 {
		err = excel.SetColWidth(sheetName, "B", lastColumn, 35)
	}
	if err != nil {
		return err
	}

	cellStyles, createCellStylesError := new(ExcelStyles).Init(excel)
	if createCellStylesError != nil {
		return fmt.Errorf("unable to create cell styles: %w", createCellStylesError)
	}

	excelRow++ // as we have a header line
	if len(sortedTagsAvailable) > 0 {
		for _, techAsset := range sortedTechnicalAssetsByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, lastColumn, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, techAsset.Title, techAsset.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
			for _, commLink := range techAsset.CommunicationLinksSorted() {
				err := writeRow(excel, &excelRow, sheetName, lastColumn, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, commLink.Title, commLink.Tags)
				if err != nil {
					return fmt.Errorf("unable to write row: %w", err)
				}
			}
		}
		for _, dataAsset := range sortedDataAssetsByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, lastColumn, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, dataAsset.Title, dataAsset.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
		for _, trustBoundary := range sortedTrustBoundariesByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, lastColumn, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, trustBoundary.Title, trustBoundary.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
		for _, sharedRuntime := range sortedSharedRuntimesByTitle(parsedModel) {
			err := writeRow(excel, &excelRow, sheetName, lastColumn, cellStyles.blackLeftBold, cellStyles.blackCenter, sortedTagsAvailable, sharedRuntime.Title, sharedRuntime.Tags)
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
	}

	err = excel.SetCellStyle(sheetName, "A1", "A1", cellStyles.headCenterBold)
	if len(sortedTagsAvailable) > 0 {
		err = excel.SetCellStyle(sheetName, "B1", lastColumn+"1", cellStyles.headCenter)
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

func sortedTrustBoundariesByTitle(parsedModel *types.Model) []*types.TrustBoundary {
	boundaries := make([]*types.TrustBoundary, 0)
	for _, boundary := range parsedModel.TrustBoundaries {
		boundaries = append(boundaries, boundary)
	}
	sort.Sort(byTrustBoundaryTitleSort(boundaries))
	return boundaries
}

type byTrustBoundaryTitleSort []*types.TrustBoundary

func (what byTrustBoundaryTitleSort) Len() int      { return len(what) }
func (what byTrustBoundaryTitleSort) Swap(i, j int) { what[i], what[j] = what[j], what[i] }
func (what byTrustBoundaryTitleSort) Less(i, j int) bool {
	return what[i].Title < what[j].Title
}

func sortedDataAssetsByTitle(parsedModel *types.Model) []*types.DataAsset {
	assets := make([]*types.DataAsset, 0)
	for _, asset := range parsedModel.DataAssets {
		assets = append(assets, asset)
	}
	sort.Sort(types.ByDataAssetTitleSort(assets))
	return assets
}

func writeRow(excel *excelize.File, excelRow *int, sheetName string, _ string, styleBlackLeftBold int, styleBlackCenter int,
	sortedTags []string, assetTitle string, tagsUsed []string) error {
	*excelRow++

	firstCellName, firstCoordinatesToCellNameError := excelize.CoordinatesToCellName(1, *excelRow)
	if firstCoordinatesToCellNameError != nil {
		return fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", 1, *excelRow, firstCoordinatesToCellNameError)
	}

	err := excel.SetCellValue(sheetName, firstCellName, assetTitle)
	if err != nil {
		return fmt.Errorf("unable to write row: %w", err)
	}

	for i, tag := range sortedTags {
		if contains(tagsUsed, tag) {
			cellName, coordinatesToCellNameError := excelize.CoordinatesToCellName(i+2, *excelRow)
			if coordinatesToCellNameError != nil {
				return fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", i+2, *excelRow, coordinatesToCellNameError)
			}

			err = excel.SetCellValue(sheetName, cellName, "X")
			if err != nil {
				return fmt.Errorf("unable to write row: %w", err)
			}
		}
	}

	err = excel.SetCellStyle(sheetName, firstCellName, firstCellName, styleBlackLeftBold)
	if err != nil {
		return fmt.Errorf("unable to write row: %w", err)
	}

	secondCellName, secondCoordinatesToCellNameError := excelize.CoordinatesToCellName(2, *excelRow)
	if secondCoordinatesToCellNameError != nil {
		return fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", 2, *excelRow, secondCoordinatesToCellNameError)
	}

	lastCellName, lastCoordinatesToCellNameError := excelize.CoordinatesToCellName(len(sortedTags)+2, *excelRow)
	if lastCoordinatesToCellNameError != nil {
		return fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", len(sortedTags)+2, *excelRow, lastCoordinatesToCellNameError)
	}

	err = excel.SetCellStyle(sheetName, secondCellName, lastCellName, styleBlackCenter)
	if err != nil {
		return fmt.Errorf("unable to write row: %w", err)
	}

	return nil
}

func removeFormattingTags(content string) string {
	result := strings.ReplaceAll(strings.ReplaceAll(content, "<b>", ""), "</b>", "")
	result = strings.ReplaceAll(strings.ReplaceAll(result, "<i>", ""), "</i>", "")
	result = strings.ReplaceAll(strings.ReplaceAll(result, "<u>", ""), "</u>", "")
	return result
}
