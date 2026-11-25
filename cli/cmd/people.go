package cmd

import (
	"fmt"

	"github.com/ente/cli/pkg"
	"github.com/spf13/cobra"
)

var peopleCmd = &cobra.Command{
	Use:   "people",
	Short: "Export or import face recognition people (names and face assignments)",
	Long: `Copy people between Ente Photos accounts that see the same photos.

People reference faces by face ID (file ID + face box). Accounts that share
the same albums get the same face IDs from the shared ML index, so a person
exported from one account resolves to the same faces in the other.

Both accounts must first be added to the CLI with 'ente account add'.`,
}

var peopleExportCmd = &cobra.Command{
	Use:   "export <output.json>",
	Short: "Export all people of a photos account to a decrypted JSON file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		if email == "" {
			return fmt.Errorf("--email is required")
		}
		return ctrl.ExportPeople(email, args[0])
	},
}

var peopleImportCmd = &cobra.Command{
	Use:   "import <input.json>",
	Short: "Create the people from an export file in another photos account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		email, _ := cmd.Flags().GetString("email")
		if email == "" {
			return fmt.Errorf("--email is required")
		}
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		update, _ := cmd.Flags().GetBool("update-existing")
		keepLinks, _ := cmd.Flags().GetBool("keep-contact-links")
		yes, _ := cmd.Flags().GetBool("yes")
		return ctrl.ImportPeople(email, args[0], pkg.PeopleImportOptions{
			DryRun:           dryRun,
			UpdateExisting:   update,
			KeepContactLinks: keepLinks,
			AssumeYes:        yes,
		})
	},
}

func init() {
	peopleExportCmd.Flags().String("email", "", "email of the source photos account")
	peopleImportCmd.Flags().String("email", "", "email of the target photos account")
	peopleImportCmd.Flags().Bool("dry-run", false, "show what would be imported without changing anything")
	peopleImportCmd.Flags().Bool("update-existing", false, "overwrite target people with the same name or imported earlier")
	peopleImportCmd.Flags().Bool("keep-contact-links", false, "keep the email/userID link of a person to an Ente user")
	peopleImportCmd.Flags().BoolP("yes", "y", false, "do not ask for confirmation")

	rootCmd.AddCommand(peopleCmd)
	peopleCmd.AddCommand(peopleExportCmd, peopleImportCmd)
}
