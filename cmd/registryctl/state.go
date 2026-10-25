package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/tg123/sshpiper/registry"
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
			if e.State != registry.StateReady {
				return fmt.Errorf("entry %d is %s: only a ready entry can be exposed", e.ID, e.State)
			}
			if p, err := db.Persona(c.Context, e.ID); err != nil || !p.HasHostKeys() {
				return fmt.Errorf("entry %d has no host keys", e.ID)
			}
			if err := db.SetState(c.Context, e.ID, registry.StateExposed, ""); err != nil {
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
			if err := db.SetState(c.Context, e.ID, registry.StateRetired, ""); err != nil {
				return err
			}
			fmt.Printf("entry %d (%s) retired\n", e.ID, e.ExternalIP)

			hook := c.String("hook-cmd")
			if hook == "" {
				return nil
			}

			cmd := exec.CommandContext(c.Context, "sh", "-c", hook)
			cmd.Env = append(os.Environ(), "EXTERNAL_IP="+e.ExternalIP, fmt.Sprintf("ENTRY_ID=%d", e.ID))
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				_ = db.AddEvent(c.Context, e.ID, "retire_hook_failed", err.Error())
				return fmt.Errorf("entry %d is retired but the hook failed: %w", e.ID, err)
			}
			_ = db.AddEvent(c.Context, e.ID, "retire_hook", "ok")
			return nil
		},
	}
}
