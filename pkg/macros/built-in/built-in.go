package builtin

import (
	"github.com/threagile/threagile/pkg/macros"
	addbuildpipeline "github.com/threagile/threagile/pkg/macros/built-in/add-build-pipeline"
	addvault "github.com/threagile/threagile/pkg/macros/built-in/add-vault"
	prettyprint "github.com/threagile/threagile/pkg/macros/built-in/pretty-print"
	removeunusedtags "github.com/threagile/threagile/pkg/macros/built-in/remove-unused-tags"
	seedrisktracking "github.com/threagile/threagile/pkg/macros/built-in/seed-risk-tracking"
	seedtags "github.com/threagile/threagile/pkg/macros/built-in/seed-tags"
)

func ListBuiltInMacros() []macros.MacroDetails {
	return []macros.MacroDetails{
		addbuildpipeline.GetMacroDetails(),
		addvault.GetMacroDetails(),
		prettyprint.GetMacroDetails(),
		removeunusedtags.GetMacroDetails(),
		seedrisktracking.GetMacroDetails(),
		seedtags.GetMacroDetails(),
	}
}
