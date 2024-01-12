package cmd

import (
	"os"

	"github.com/cybozu-go/neco-bpftools/socket-tracer/pkg/bpf"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "socket-tracer",
	Short: "trace socket syscall",
	RunE: func(cmd *cobra.Command, args []string) error {
		familyStr, err := cmd.Flags().GetString("family")
		if err != nil {
			return err
		}
		family, err := bpf.ParseFamily(familyStr)
		if err != nil {
			return err
		}

		return bpf.TraceEnterSocket(family)
	},
}

func init() {
	rootCmd.Flags().StringP("family", "f", "", "Family value for socket system call. See `man socket`. Accepts AF_* or number")
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
