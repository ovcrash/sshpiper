// Package relayadmin holds the operations that fill and drive the registry:
// add, persona (generate/import/export), probe, expose, retire. It imports
// both registry and sshprobe (which registry cannot, since sshprobe imports
// registry), so it is the shared layer under both registryctl and the
// registration API (relay-admind). It never prints: it returns values and
// errors.
package relayadmin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/tg123/sshpiper/registry"
)

// Service runs registry operations against one open database.
type Service struct {
	db *registry.DB
}

// New wraps an open registry (opened read-write by the caller).
func New(db *registry.DB) *Service { return &Service{db: db} }

// DB returns the underlying registry.
func (s *Service) DB() *registry.DB { return s.db }

// AddEntry validates and inserts a new entry (state draft).
func (s *Service) AddEntry(ctx context.Context, n registry.NewEntry) (*registry.Entry, error) {
	return s.db.Create(ctx, n)
}

// List returns all entries (optionally filtered by state).
func (s *Service) List(ctx context.Context, states ...registry.State) ([]*registry.Entry, error) {
	return s.db.List(ctx, states...)
}

// Get returns one entry by external IP.
func (s *Service) Get(ctx context.Context, ip string) (*registry.Entry, error) {
	return s.db.ByExternalIP(ctx, ip)
}

// Persona returns the persona of an entry (ErrNotFound if none).
func (s *Service) Persona(ctx context.Context, id int64) (*registry.Persona, error) {
	return s.db.Persona(ctx, id)
}

// Events returns the event log of an entry.
func (s *Service) Events(ctx context.Context, id int64) ([]registry.Event, error) {
	return s.db.Events(ctx, id)
}

// GenPersona generates the three host keys for an entry. force replaces
// existing keys. It refuses to change the keys of an exposed entry.
func (s *Service) GenPersona(ctx context.Context, e *registry.Entry, force bool) error {
	if err := guardKeyChange(e); err != nil {
		return err
	}
	p, err := s.loadOrNewPersona(ctx, e.ID)
	if err != nil {
		return err
	}
	if p.HasHostKeys() && !force {
		return fmt.Errorf("entry %d already has host keys (use force to replace them)", e.ID)
	}
	hk, err := registry.GenerateHostKeys()
	if err != nil {
		return err
	}
	p.SetHostKeys(*hk)
	return s.db.SetPersona(ctx, *p, "persona_generated", "host keys generated")
}

// ImportPersonaKeys stores host keys given by the caller (e.g. taken from the
// VM). It refuses to change the keys of an exposed entry.
func (s *Service) ImportPersonaKeys(ctx context.Context, e *registry.Entry, hk registry.HostKeys) error {
	if err := guardKeyChange(e); err != nil {
		return err
	}
	if err := hk.Validate(); err != nil {
		return err
	}
	p, err := s.loadOrNewPersona(ctx, e.ID)
	if err != nil {
		return err
	}
	p.SetHostKeys(hk)
	return s.db.SetPersona(ctx, *p, "persona_generated", "host keys imported")
}

// ExportKeys returns the host private keys of an entry (to install on the VM).
func (s *Service) ExportKeys(ctx context.Context, id int64) (registry.HostKeys, error) {
	p, err := s.db.Persona(ctx, id)
	if err != nil {
		return registry.HostKeys{}, err
	}
	if !p.HasHostKeys() {
		return registry.HostKeys{}, fmt.Errorf("entry %d has no host keys", id)
	}
	return p.HostKeys(), nil
}

// Expose puts a ready account into service. It requires the site persona of
// the account's external IP to have presented host keys.
func (s *Service) Expose(ctx context.Context, e *registry.Entry) error {
	if e.State != registry.StateReady {
		return fmt.Errorf("entry %d is %s: only a ready entry can be exposed", e.ID, e.State)
	}
	if p, err := s.db.SitePersona(ctx, e.ExternalIP); err != nil || !p.HasHostKeys() {
		return fmt.Errorf("site %s has no host keys (generate or import them first)", e.ExternalIP)
	}
	return s.moveTo(ctx, e, registry.StateExposed, "")
}

// --- site persona (per external IP, presented at KEX) ---

// SitePersona returns the persona presented on an external IP (ErrNotFound if none).
func (s *Service) SitePersona(ctx context.Context, ip string) (*registry.Persona, error) {
	return s.db.SitePersona(ctx, ip)
}

// GenSitePersona generates the three presented host keys for a site. force
// replaces existing keys. It refuses to change keys while any account on the IP
// is exposed.
func (s *Service) GenSitePersona(ctx context.Context, ip string, force bool) error {
	if err := s.guardSiteKeyChange(ctx, ip); err != nil {
		return err
	}
	p, err := s.loadOrNewSitePersona(ctx, ip)
	if err != nil {
		return err
	}
	if p.HasHostKeys() && !force {
		return fmt.Errorf("site %s already has host keys (use force to replace them)", ip)
	}
	hk, err := registry.GenerateHostKeys()
	if err != nil {
		return err
	}
	p.SetHostKeys(*hk)
	return s.db.SetSitePersona(ctx, ip, *p)
}

// ImportSitePersonaKeys stores presented host keys given by the caller.
func (s *Service) ImportSitePersonaKeys(ctx context.Context, ip string, hk registry.HostKeys) error {
	if err := s.guardSiteKeyChange(ctx, ip); err != nil {
		return err
	}
	if err := hk.Validate(); err != nil {
		return err
	}
	p, err := s.loadOrNewSitePersona(ctx, ip)
	if err != nil {
		return err
	}
	p.SetHostKeys(hk)
	return s.db.SetSitePersona(ctx, ip, *p)
}

// ExportSiteKeys returns the presented private host keys of a site.
func (s *Service) ExportSiteKeys(ctx context.Context, ip string) (registry.HostKeys, error) {
	p, err := s.db.SitePersona(ctx, ip)
	if err != nil {
		return registry.HostKeys{}, err
	}
	if !p.HasHostKeys() {
		return registry.HostKeys{}, fmt.Errorf("site %s has no host keys", ip)
	}
	return p.HostKeys(), nil
}

func (s *Service) loadOrNewSitePersona(ctx context.Context, ip string) (*registry.Persona, error) {
	p, err := s.db.SitePersona(ctx, ip)
	if errors.Is(err, registry.ErrNotFound) {
		return &registry.Persona{}, nil
	}
	return p, err
}

// guardSiteKeyChange refuses a persona key change while any account on the IP
// is exposed.
func (s *Service) guardSiteKeyChange(ctx context.Context, ip string) error {
	accs, err := s.db.ListByIP(ctx, ip)
	if err != nil && !errors.Is(err, registry.ErrNotFound) {
		return err
	}
	for _, a := range accs {
		if a.State == registry.StateExposed {
			return errors.New("refusing to change host keys while an account on this IP is exposed: retire it first")
		}
	}
	return nil
}

// Retire stops serving an entry.
func (s *Service) Retire(ctx context.Context, e *registry.Entry) error {
	return s.moveTo(ctx, e, registry.StateRetired, "")
}

// Reactivate brings a retired entry back to draft so it can be probed and
// exposed again; its persona and credentials are kept. It fails if another
// live entry already holds the same external IP (registry.ErrExists).
func (s *Service) Reactivate(ctx context.Context, e *registry.Entry) error {
	if e.State != registry.StateRetired {
		return fmt.Errorf("entry %d is %s: only a retired entry can be reactivated", e.ID, e.State)
	}
	return s.moveTo(ctx, e, registry.StateDraft, "reactivated")
}

// RunRetireHook runs a shell command after a retire, with EXTERNAL_IP and
// ENTRY_ID in the environment (to remove or firewall the address), and
// records the outcome. A nil hookCmd is a no-op.
func (s *Service) RunRetireHook(ctx context.Context, e *registry.Entry, hookCmd string) error {
	if hookCmd == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", hookCmd)
	cmd.Env = append(os.Environ(), "EXTERNAL_IP="+e.ExternalIP, fmt.Sprintf("ENTRY_ID=%d", e.ID))
	out, err := cmd.CombinedOutput()
	if err != nil {
		_ = s.db.AddEvent(ctx, e.ID, "retire_hook_failed", err.Error())
		return fmt.Errorf("retire hook failed: %w: %s", err, string(out))
	}
	_ = s.db.AddEvent(ctx, e.ID, "retire_hook", "ok")
	return nil
}

func (s *Service) loadOrNewPersona(ctx context.Context, id int64) (*registry.Persona, error) {
	p, err := s.db.Persona(ctx, id)
	if errors.Is(err, registry.ErrNotFound) {
		return &registry.Persona{EntryID: id}, nil
	}
	return p, err
}

func guardKeyChange(e *registry.Entry) error {
	if e.State == registry.StateExposed {
		return errors.New("refusing to change host keys of an exposed entry: retire it first")
	}
	return nil
}
