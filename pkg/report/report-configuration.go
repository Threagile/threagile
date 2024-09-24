package report

type ChaptersToShowHide string

const (
	RiskRulesCheckedByThreagile ChaptersToShowHide = "RiskRulesCheckedByThreagile"
)

type ReportConfiguation struct {
	ShowChapter map[ChaptersToShowHide]bool
}
