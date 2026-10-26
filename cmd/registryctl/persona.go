package main

import (
	"fmt"

	"github.com/tg123/sshpiper/registry"
	"github.com/tg123/sshpiper/relayadmin"
	"github.com/urfave/cli/v2"
)

func personaCommand() *cli.Command {
	return &cli.Command{
		Name:  "persona",
		Usage: "manage the host keys presented on an external IP",
		Subcommands: []*cli.Command{
			{
				Name:  "gen",
				Usage: "generate ed25519, ECDSA P-256 and RSA 3072 host keys",
				Flags: append(idFlags(), &cli.BoolFlag{Name: "force", Usage: "replace existing host keys"}),
				Action: func(c *cli.Context) error {
					db, err := openDB(c, false)
					if err != nil {
						return err
					}
					defer db.Close()
					e, err := findEntry(c, db)
					if err != nil {
						return err
					}
					if err := relayadmin.New(db).GenPersona(c.Context, e, c.Bool("force")); err != nil {
						return err
					}
					fmt.Printf("host keys generated for entry %d\n", e.ID)
					return nil
				},
			},
			{
				Name:  "export-keys",
				Usage: "write ssh_host_*_key files (and .pub) for the backend",
				Flags: append(idFlags(), &cli.StringFlag{Name: "dir", Usage: "output directory", Required: true}),
				Action: func(c *cli.Context) error {
					db, err := openDB(c, true)
					if err != nil {
						return err
					}
					defer db.Close()
					e, err := findEntry(c, db)
					if err != nil {
						return err
					}
					hk, err := relayadmin.New(db).ExportKeys(c.Context, e.ID)
					if err != nil {
						return err
					}
					if err := registry.ExportHostKeys(c.String("dir"), hk); err != nil {
						return err
					}
					fmt.Printf("host keys written to %s\n", c.String("dir"))
					return nil
				},
			},
			{
				Name:  "import",
				Usage: "take the host keys from a directory laid out like /etc/ssh",
				Flags: append(idFlags(), &cli.StringFlag{Name: "from", Usage: "directory with ssh_host_*_key", Required: true}),
				Action: func(c *cli.Context) error {
					db, err := openDB(c, false)
					if err != nil {
						return err
					}
					defer db.Close()
					e, err := findEntry(c, db)
					if err != nil {
						return err
					}
					hk, err := registry.ImportHostKeys(c.String("from"))
					if err != nil {
						return err
					}
					if err := relayadmin.New(db).ImportPersonaKeys(c.Context, e, *hk); err != nil {
						return err
					}
					fmt.Printf("host keys imported for entry %d\n", e.ID)
					return nil
				},
			},
		},
	}
}
