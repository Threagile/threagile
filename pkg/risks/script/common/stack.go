package common

import (
	"github.com/threagile/threagile/pkg/risks/script/event"
)

type Stack []event.History

func (what Stack) History(events ...event.Event) event.History {
	history := events
	for _, frame := range what {
		history = append(history, frame...)
	}

	return history
}
