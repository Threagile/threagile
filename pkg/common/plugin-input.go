package common

import (
	"github.com/threagile/threagile/pkg/model"
)

type PluginInput struct {
	Config
	model.ParsedModel
}
