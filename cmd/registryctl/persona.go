package main

import (
	"errors"
	"fmt"

	"github.com/tg123/sshpiper/registry"
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
					p, err := loadOrNewPersona(c, db, e.ID)
					if err != nil {
						return err
					}
					if p.HasHostKeys() && !c.Bool("force") {
						return fmt.Errorf("entry %d already has host keys (use --force to replace them)", e.ID)
					}
					if e.State == registry.StateExposed {
						return errors.New("refusing to change host keys of an exposed entry: retire it first")
					}

					hk, err := registry.GenerateHostKeys()
					if err != nil {
						return err
					}
					p.SetHostKeys(*hk)
					if err := db.SetPersona(c.Context, *p, "persona_generated", "host keys generated"); err != nil {
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
					p, err := db.Persona(c.Context, e.ID)
					if err != nil || !p.HasHostKeys() {
						return fmt.Errorf("entry %d has no host keys: run persona gen or persona import", e.ID)
					}
					if err := registry.ExportHostKeys(c.String("dir"), p.HostKeys()); err != nil {
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
					if e.State == registry.StateExposed {
						return errors.New("refusing to change host keys of an exposed entry: retire it first")
					}
					hk, err := registry.ImportHostKeys(c.String("from"))
					if err != nil {
						return err
					}
					p, err := loadOrNewPersona(c, db, e.ID)
					if err != nil {
						return err
					}
					p.SetHostKeys(*hk)
					if err := db.SetPersona(c.Context, *p, "persona_generated", "host keys imported"); err != nil {
						return err
					}
					fmt.Printf("host keys imported for entry %d\n", e.ID)
					return nil
				},
			},
		},
	}
}

func loadOrNewPersona(c *cli.Context, db *registry.DB, entryID int64) (*registry.Persona, error) {
	p, err := db.Persona(c.Context, entryID)
	if errors.Is(err, registry.ErrNotFound) {
		return &registry.Persona{EntryID: entryID}, nil
	}
	return p, err
}
