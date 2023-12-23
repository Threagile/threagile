package common

type Config struct {
	Verbose                    bool
	IgnoreOrphanedRiskTracking bool
	OutputDir                  string
	RAAPlugin                  string
	SkipRiskRules              string
	RiskRulesPlugins           string
	ModelFilename              string
	TemplateFilename           string
	ExecuteModelMacro          string
	DiagramDPI                 int
	ServerPort                 int
	AddModelTitle              bool
	KeepDiagramSourceFiles     bool
	AppFolder                  string
	BinFolder                  string
	ServerFolder               string
	TempFolder                 string
	DefaultGraphvizDPI         int
	MaxGraphvizDPI             int
	Attractiveness             Attractiveness
}

func (c *Config) Defaults() *Config {
	*c = Config{
		DefaultGraphvizDPI: 120,
		MaxGraphvizDPI:     240,
	}

	return c
}
