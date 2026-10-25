package audit

import (
	"encoding/json"
	"fmt"
	"time"
)

// castFile is the per-channel recording name.
func castFile(id uint32) string { return fmt.Sprintf("channel-%d.cast", id) }

// openCast writes the asciicast v2 header for a channel if not already open.
func (s *Session) openCast(id uint32) {
	s.mu.Lock()
	c := s.chans[id]
	if c == nil {
		c = &chanState{}
		s.chans[id] = c
	}
	if c.started {
		s.mu.Unlock()
		return
	}
	c.started = true
	c.start = time.Now()
	width, height, term := c.width, c.height, c.term
	env := map[string]string{}
	for k, v := range s.envOnly {
		env[k] = v
	}
	s.mu.Unlock()

	if term != "" {
		env["TERM"] = term
	}
	header := map[string]any{
		"version":   2,
		"width":     width,
		"height":    height,
		"timestamp": c.start.Unix(),
		"env":       env,
	}
	b, err := json.Marshal(header)
	if err != nil {
		return
	}
	s.w.appendFile(s.id, castFile(id), append(b, '\n'))
}

func (s *Session) castElapsed(id uint32) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.chans[id]
	if c == nil || !c.started {
		return 0, false
	}
	return time.Since(c.start).Seconds(), true
}

// castAppend writes one asciicast event ("i" input, "o" output).
func (s *Session) castAppend(id uint32, code string, raw []byte) {
	t, ok := s.castElapsed(id)
	if !ok {
		// data before a shell/exec request: open the cast lazily
		s.openCast(id)
		if t, ok = s.castElapsed(id); !ok {
			return
		}
	}
	line := fmt.Sprintf("[%s,%q,%s]\n", formatSeconds(t), code, jsonString(raw))
	s.w.appendFile(s.id, castFile(id), []byte(line))
}

// castResize writes an asciicast resize event ("r").
func (s *Session) castResize(id uint32, width, height uint32) {
	t, ok := s.castElapsed(id)
	if !ok {
		return
	}
	size := fmt.Sprintf("%dx%d", width, height)
	line := fmt.Sprintf("[%s,%q,%s]\n", formatSeconds(t), "r", jsonString([]byte(size)))
	s.w.appendFile(s.id, castFile(id), []byte(line))
}

func formatSeconds(t float64) string {
	return fmt.Sprintf("%.6f", t)
}
