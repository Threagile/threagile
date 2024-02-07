package threagile

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/common"
	"github.com/threagile/threagile/pkg/docs"
)

func (what *Threagile) initVersion() *Threagile {
	what.rootCmd.AddCommand(&cobra.Command{
		Use:   common.PrintVersionCommand,
		Short: "Get version information",
		Long:  "\n" + docs.Logo + "\n\n" + fmt.Sprintf(docs.VersionText, what.buildTimestamp),
	})

	return what
}
