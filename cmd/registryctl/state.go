package main

import (
	"fmt"

	"github.com/tg123/sshpiper/relayadmin"
	"github.com/urfave/cli/v2"
)

func exposeCommand() *cli.Command {
	return &cli.Command{
		Name:  "expose",
		Usage: "put a ready entry into service",
		Flags: idFlags(),
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
			if err := relayadmin.New(db).Expose(c.Context, e); err != nil {
				return err
			}
			fmt.Printf("entry %d (%s) exposed\n", e.ID, e.ExternalIP)
			return nil
		},
	}
}

func retireCommand() *cli.Command {
	return &cli.Command{
		Name:  "retire",
		Usage: "stop serving an entry, then run the retire hook",
		Flags: append(idFlags(), &cli.StringFlag{
			Name:    "hook-cmd",
			Usage:   "shell command run after retiring, with EXTERNAL_IP and ENTRY_ID set (remove the address or block it)",
			EnvVars: []string{"RELAY_RETIRE_HOOK"},
		}),
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
			svc := relayadmin.New(db)
			if err := svc.Retire(c.Context, e); err != nil {
				return err
			}
			fmt.Printf("entry %d (%s) retired\n", e.ID, e.ExternalIP)
			if err := svc.RunRetireHook(c.Context, e, c.String("hook-cmd")); err != nil {
				return fmt.Errorf("entry %d is retired but the hook failed: %w", e.ID, err)
			}
			return nil
		},
	}
}
