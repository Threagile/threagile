package report

type ChaptersToShowHide string

const (
	RiskRulesCheckedByThreagile ChaptersToShowHide = "RiskRulesCheckedByThreagile"
)

type ReportConfiguation struct {
	HideChapter map[ChaptersToShowHide]bool
}
