package audit

import (
	"path"
	"strconv"
	"strings"
)

// scpParser follows the legacy scp protocol in the sending direction: control
// lines ("C<mode> <size> <name>", "D...", "E", "T...") and, after each C line,
// the file body followed by one status byte.
type scpParser struct {
	sess    *Session
	channel uint32
	dir     string // upload (client sends) or download (backend sends)
	target  string // path from the scp command line

	line      []byte
	cur       *transfer
	remaining int64
	offset    int64
	trailer   bool // expecting the status byte after a file body
	dead      bool
}

const scpMaxLine = 4096

// newSCPParser returns a parser for an exec command line, or nil if the
// command is not a legacy scp sink (-t) or source (-f).
func newSCPParser(sess *Session, channel uint32, command string) *scpParser {
	f := strings.Fields(command)
	if len(f) < 2 || path.Base(f[0]) != "scp" {
		return nil
	}
	dir := ""
	target := ""
	for i := 1; i < len(f); i++ {
		a := f[i]
		switch {
		case a == "--":
			if i+1 < len(f) {
				target = strings.Join(f[i+1:], " ")
			}
			i = len(f)
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if strings.Contains(a, "t") {
				dir = "upload"
			}
			if strings.Contains(a, "f") {
				dir = "download"
			}
		default:
			target = strings.Join(f[i:], " ")
			i = len(f)
		}
	}
	if dir == "" {
		return nil
	}
	return &scpParser{sess: sess, channel: channel, dir: dir, target: unquote(target)}
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// feed consumes bytes of the sending direction.
func (p *scpParser) feed(b []byte) {
	for len(b) > 0 && !p.dead {
		switch {
		case p.cur != nil && p.remaining > 0:
			n := int64(len(b))
			if n > p.remaining {
				n = p.remaining
			}
			p.cur.write(p.offset, b[:n])
			p.offset += n
			p.remaining -= n
			b = b[n:]
			if p.remaining == 0 {
				p.cur.finish(false)
				p.cur = nil
				p.trailer = true
			}
		case p.trailer:
			p.trailer = false
			b = b[1:] // status byte (0 = ok)
		default:
			i := indexByte(b, '\n')
			if i < 0 {
				p.line = append(p.line, b...)
				if len(p.line) > scpMaxLine {
					p.dead = true
				}
				return
			}
			p.line = append(p.line, b[:i]...)
			b = b[i+1:]
			p.control(string(p.line))
			p.line = p.line[:0]
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// control handles one scp control line.
func (p *scpParser) control(line string) {
	if line == "" {
		return
	}
	switch line[0] {
	case 'C': // C0644 1234 name
		parts := strings.SplitN(line[1:], " ", 3)
		if len(parts) != 3 {
			return
		}
		size, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || size < 0 {
			return
		}
		name := parts[2]
		p.cur = p.sess.startTransfer("scp", p.dir, p.channel, p.target, name)
		p.remaining = size
		p.offset = 0
		if size == 0 {
			p.cur.finish(false)
			p.cur = nil
			p.trailer = true
		}
	case 'D', 'E', 'T':
		// directory enter/leave and timestamps: no file body
	default:
		// '\x01'/'\x02' are scp warning/error messages; ignore
	}
}

// close ends an scp transfer still in progress (channel or session ended).
func (p *scpParser) close() {
	if p.cur != nil {
		p.cur.finish(true)
		p.cur = nil
	}
}
