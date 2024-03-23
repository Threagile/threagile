package report

import (
	"github.com/xuri/excelize/v2"
	"strings"
)

type ExcelColumns map[string]ExcelColumn

func (what *ExcelColumns) GetColumns() ExcelColumns {
	*what = map[string]ExcelColumn{
		"A": {Title: "Severity", Width: 12},
		"B": {Title: "Likelihood", Width: 15},
		"C": {Title: "Impact", Width: 15},
		"D": {Title: "STRIDE", Width: 22},
		"E": {Title: "Function", Width: 16},
		"F": {Title: "CWE", Width: 12},
		"G": {Title: "Risk Category", Width: 50},
		"H": {Title: "Technical Asset", Width: 50},
		"I": {Title: "Communication Link", Width: 50},
		"J": {Title: "RAA %", Width: 10},
		"K": {Title: "Identified Risk", Width: 75},
		"L": {Title: "Action", Width: 45},
		"M": {Title: "Mitigation", Width: 75},
		"N": {Title: "Check", Width: 40},
		"O": {Title: "ID", Width: 10},
		"P": {Title: "Status", Width: 18},
		"Q": {Title: "Justification", Width: 80},
		"R": {Title: "Date", Width: 18},
		"S": {Title: "Checked by", Width: 20},
		"T": {Title: "Ticket", Width: 20},
	}

	return *what
}

func (what *ExcelColumns) FindColumnNameByTitle(title string) string {
	for column, excelColumn := range *what {
		if strings.EqualFold(excelColumn.Title, title) {
			return column
		}
	}

	return ""
}

func (what *ExcelColumns) FindColumnIndexByTitle(title string) int {
	for column, excelColumn := range *what {
		if strings.EqualFold(excelColumn.Title, title) {
			columnNumber, columnNumberError := excelize.ColumnNameToNumber(column)
			if columnNumberError != nil {
				return -1
			}

			return columnNumber - 1
		}
	}

	return -1
}

type ExcelColumn struct {
	Title string
	Width float64
}
