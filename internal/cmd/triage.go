/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/openvex/vexctl/internal/triage"
	"github.com/openvex/vexctl/pkg/formats/grypejson"
	"github.com/spf13/cobra"
)

func addTriage(parentCmd *cobra.Command) {
	cmd := &cobra.Command{
		Use:  "triage",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// resolve input file

			scanReportFilepath := args[0]
			f, err := os.Open(scanReportFilepath)
			if err != nil {
				return err
			}
			defer f.Close()

			parsed, err := grypejson.Parse(f)
			if err != nil {
				return err
			}

			// start app

			p := tea.NewProgram(triage.NewModel(parsed.Normalized()), tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				return err
			}

			// either just exit, or exit + write output file (VEX)

			return nil
		},
	}

	parentCmd.AddCommand(cmd)
}
