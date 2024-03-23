package report

import (
	"fmt"
	"github.com/mpvl/unique"
	"github.com/xuri/excelize/v2"
	"sort"
)

type RiskGroup struct {
	Groups map[string]*RiskGroup
	Items  []RiskItem
}

func (what *RiskGroup) Init(riskItems []RiskItem) *RiskGroup {
	*what = RiskGroup{
		Groups: make(map[string]*RiskGroup),
		Items:  riskItems,
	}

	return what
}

func (what *RiskGroup) SortedGroups() []string {
	groups := make([]string, 0)
	for group := range what.Groups {
		groups = append(groups, group)
	}

	sort.Strings(groups)
	unique.Strings(&groups)

	return groups
}

func (what *RiskGroup) Make(riskItems []RiskItem, columns ExcelColumns, groupBy []string) (*RiskGroup, error) {
	what.Init(riskItems)

	if len(groupBy) == 0 {
		return what, nil
	}

	groupName, groupBy := groupBy[0], groupBy[1:]
	column := columns.FindColumnIndexByTitle(groupName)
	if column < 0 {
		return what, fmt.Errorf("unable to find column %q", groupName)
	}

	values := what.uniqueValues(column)
	for _, value := range values {
		subItems := make([]RiskItem, 0)
		for _, item := range what.Items {
			if item.Columns[column] == value {
				subItems = append(subItems, item)
			}
		}

		group, groupError := new(RiskGroup).Make(subItems, columns, groupBy)
		if groupError != nil {
			return what, fmt.Errorf("unable to create group: %w", groupError)
		}

		what.Groups[value] = group
	}

	return what, nil
}

func (what *RiskGroup) Write(excel *excelize.File, sheetName string, cellStyles *ExcelStyles) error {
	if len(what.Groups) == 0 {
		_, writeError := what.writeGroup(excel, sheetName, cellStyles, 0)
		return writeError
	}

	var writeError error
	excelRow := 0
	for _, group := range what.SortedGroups() {
		excelRow, writeError = what.Groups[group].writeGroup(excel, sheetName, cellStyles, excelRow)
		if writeError != nil {
			return writeError
		}
	}

	return writeError
}

func (what *RiskGroup) writeGroup(excel *excelize.File, sheetName string, cellStyles *ExcelStyles, excelRow int) (int, error) {
	for _, risk := range what.Items {
		excelRow++

		for columnIndex, column := range risk.Columns {
			cellName, coordinatesToCellNameError := excelize.CoordinatesToCellName(columnIndex+1, excelRow+1)
			if coordinatesToCellNameError != nil {
				return excelRow, fmt.Errorf("failed to get cell coordinates from [%d, %d]: %w", columnIndex+1, excelRow+1, coordinatesToCellNameError)
			}

			setCellValueError := excel.SetCellValue(sheetName, cellName, column)
			if setCellValueError != nil {
				return excelRow, setCellValueError
			}

			columnName, columnNameError := excelize.ColumnNumberToName(columnIndex + 1)
			if columnNameError != nil {
				return excelRow, fmt.Errorf("failed to get cell coordinates from column [%d]: %w", columnIndex+1, columnNameError)
			}

			setCellStyleError := excel.SetCellStyle(sheetName, cellName, cellName, cellStyles.Get(columnName, risk.Status, risk.Severity))
			if setCellStyleError != nil {
				return excelRow, fmt.Errorf("failed to set cell style: %w", setCellStyleError)
			}
		}
	}

	return excelRow, nil
}

func (what *RiskGroup) uniqueValues(column int) []string {
	values := make([]string, 0)
	for _, risk := range what.Items {
		values = append(values, risk.Columns[column])
	}

	sort.Strings(values)
	unique.Strings(&values)

	return values
}
