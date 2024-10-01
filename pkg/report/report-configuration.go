package report

type ChaptersToShowHide string

const (
	RiskRulesCheckedByThreagile ChaptersToShowHide = "RiskRulesCheckedByThreagile"
	AssetRegister               ChaptersToShowHide = "AssetRegister"
)

type ReportConfiguation struct {
	HideChapter map[ChaptersToShowHide]bool
}
