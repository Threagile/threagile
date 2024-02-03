package common

import (
	"github.com/threagile/threagile/pkg/security/types"
)

type PluginInput struct {
	Config
	types.ParsedModel
}
