package main

import (
	"fmt"

	"github.com/tg123/sshpiper/registry"
	"github.com/tg123/sshpiper/relayadmin"
	"github.com/urfave/cli/v2"
)

func ipFlag() cli.Flag {
	return &cli.StringFlag{Name: "ip", Usage: "external IP (site)", Required: true}
}

func personaCommand() *cli.Command {
	return &cli.Command{
		Name:  "persona",
		Usage: "manage the host keys presented on an external IP (the site persona)",
		Subcommands: []*cli.Command{
			{
				Name:  "gen",
				Usage: "generate ed25519, ECDSA P-256 and RSA 3072 host keys for a site",
				Flags: []cli.Flag{ipFlag(), &cli.BoolFlag{Name: "force", Usage: "replace existing host keys"}},
				Action: func(c *cli.Context) error {
					db, err := openDB(c, false)
					if err != nil {
						return err
					}
					defer db.Close()
					ip := c.String("ip")
					if err := relayadmin.New(db).GenSitePersona(c.Context, ip, c.Bool("force")); err != nil {
						return err
					}
					fmt.Printf("host keys generated for site %s\n", ip)
					return nil
				},
			},
			{
				Name:  "export-keys",
				Usage: "write ssh_host_*_key files (and .pub) — the presented site keys",
				Flags: []cli.Flag{ipFlag(), &cli.StringFlag{Name: "dir", Usage: "output directory", Required: true}},
				Action: func(c *cli.Context) error {
					db, err := openDB(c, true)
					if err != nil {
						return err
					}
					defer db.Close()
					hk, err := relayadmin.New(db).ExportSiteKeys(c.Context, c.String("ip"))
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
				Usage: "take the presented site keys from a directory laid out like /etc/ssh",
				Flags: []cli.Flag{ipFlag(), &cli.StringFlag{Name: "from", Usage: "directory with ssh_host_*_key", Required: true}},
				Action: func(c *cli.Context) error {
					db, err := openDB(c, false)
					if err != nil {
						return err
					}
					defer db.Close()
					hk, err := registry.ImportHostKeys(c.String("from"))
					if err != nil {
						return err
					}
					ip := c.String("ip")
					if err := relayadmin.New(db).ImportSitePersonaKeys(c.Context, ip, *hk); err != nil {
						return err
					}
					fmt.Printf("host keys imported for site %s\n", ip)
					return nil
				},
			},
		},
	}
}
