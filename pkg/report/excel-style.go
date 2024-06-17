package report

import (
	"fmt"
	"strings"

	"github.com/threagile/threagile/pkg/types"
	"github.com/xuri/excelize/v2"
)

type ExcelStyles struct {
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

type styleCreator struct {
	ExcelFile *excelize.File
	Error     error
}

func (what *styleCreator) Init(excel *excelize.File) *styleCreator {
	what.ExcelFile = excel
	return what
}

func (what *styleCreator) NewStyle(style *excelize.Style) int {
	if what.Error != nil {
		return 0
	}

	var styleID int
	styleID, what.Error = what.ExcelFile.NewStyle(style)

	return styleID
}

func (what *ExcelStyles) Init(excel *excelize.File) (*ExcelStyles, error) {
	if excel == nil {
		return what, fmt.Errorf("no excel file provided to create styles")
	}

	creator := new(styleCreator).Init(excel)

	what.severityCriticalBold = creator.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorCriticalRisk(),
			Size:  12,
			Bold:  true,
		},
	})

	what.severityCriticalCenter = creator.NewStyle(&excelize.Style{
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

	what.severityHighBold = creator.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorHighRisk(),
			Size:  12,
			Bold:  true,
		},
	})

	what.severityHighCenter = creator.NewStyle(&excelize.Style{
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

	what.severityElevatedBold = creator.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorElevatedRisk(),
			Size:  12,
			Bold:  true,
		},
	})

	what.severityElevatedCenter = creator.NewStyle(&excelize.Style{
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

	what.severityMediumBold = creator.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorMediumRisk(),
			Size:  12,
			Bold:  true,
		},
	})

	what.severityMediumCenter = creator.NewStyle(&excelize.Style{
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

	what.severityLowBold = creator.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: rgbHexColorLowRisk(),
			Size:  12,
			Bold:  true,
		},
	})

	what.severityLowCenter = creator.NewStyle(&excelize.Style{
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

	what.redCenter = creator.NewStyle(&excelize.Style{
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

	what.greenCenter = creator.NewStyle(&excelize.Style{
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

	what.blueCenter = creator.NewStyle(&excelize.Style{
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

	what.yellowCenter = creator.NewStyle(&excelize.Style{
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

	what.orangeCenter = creator.NewStyle(&excelize.Style{
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

	what.grayCenter = creator.NewStyle(&excelize.Style{
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

	what.blackLeft = creator.NewStyle(&excelize.Style{
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

	what.blackCenter = creator.NewStyle(&excelize.Style{
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

	what.blackRight = creator.NewStyle(&excelize.Style{
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

	what.blackSmall = creator.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			ShrinkToFit: true,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  10,
		},
	})

	what.graySmall = creator.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			ShrinkToFit: true,
		},
		Font: &excelize.Font{
			Color: rgbHexColorOutOfScope(),
			Size:  10,
		},
	})

	what.blackBold = creator.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal:  "center",
			ShrinkToFit: true,
			WrapText:    false,
		},
		Font: &excelize.Font{
			Color: "#000000",
			Size:  12,
			Bold:  true,
		},
	})

	what.blackLeftBold = creator.NewStyle(&excelize.Style{
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

	what.mitigation = creator.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			ShrinkToFit: true,
		},
		Font: &excelize.Font{
			Color: rgbHexColorRiskStatusMitigated(),
			Size:  10,
		},
	})

	what.headCenterBoldItalic = creator.NewStyle(&excelize.Style{
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

	what.headCenterBold = creator.NewStyle(&excelize.Style{
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

	what.headCenter = creator.NewStyle(&excelize.Style{
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

	return what, creator.Error
}

func (what *ExcelStyles) Get(column string, status types.RiskStatus, severity types.RiskSeverity) int {
	switch strings.ToUpper(column) {
	case "A", "B", "C", "D", "E", "F":
		if !status.IsStillAtRisk() {
			return what.blackCenter
		}

		switch severity {
		case types.CriticalSeverity:
			return what.severityCriticalCenter

		case types.HighSeverity:
			return what.severityHighCenter

		case types.ElevatedSeverity:
			return what.severityElevatedCenter

		case types.MediumSeverity:
			return what.severityMediumCenter

		case types.LowSeverity:
			return what.severityLowCenter
		}

	case "G", "H", "I":
		if !status.IsStillAtRisk() {
			return what.blackBold
		}

		switch severity {
		case types.CriticalSeverity:
			return what.severityCriticalBold

		case types.HighSeverity:
			return what.severityHighBold

		case types.ElevatedSeverity:
			return what.severityElevatedBold

		case types.MediumSeverity:
			return what.severityMediumBold

		case types.LowSeverity:
			return what.severityLowBold
		}

	case "J":
		return what.blackRight

	case "K":
		return what.blackSmall

	case "L", "M", "N":
		return what.mitigation

	case "O":
		return what.graySmall

	case "P":
		switch status {
		case types.Unchecked:
			return what.redCenter

		case types.Mitigated:
			return what.greenCenter

		case types.InProgress:
			return what.blueCenter

		case types.Accepted:
			return what.yellowCenter

		case types.InDiscussion:
			return what.orangeCenter

		case types.FalsePositive:
			return what.grayCenter

		default:
			return what.blackCenter
		}

	case "Q":
		return what.blackSmall

	case "R", "S":
		return what.blackCenter

	case "T":
		return what.blackLeft
	}

	return what.blackRight
}
