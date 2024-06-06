package threagile

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/common"
)

func (what *Threagile) initVersion() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.PrintVersionCommand,
		Short: "Get version information",
		Long:  "\n" + common.Logo + "\n\n" + fmt.Sprintf(common.VersionText, what.buildTimestamp),
	})

	return what
}
