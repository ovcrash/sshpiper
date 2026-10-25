package audit

import "encoding/binary"

// SFTP packet types (RFC draft-ietf-secsh-filexfer-02, used by OpenSSH).
const (
	fxpOpen   = 3
	fxpClose  = 4
	fxpRead   = 5
	fxpWrite  = 6
	fxpHandle = 102
	fxpData   = 103

	fxfRead  = 0x00000001
	fxfWrite = 0x00000002
)

// sftpMaxPacket bounds one reassembled SFTP packet; a larger length stops the
// parsing of that stream (it is then out of sync or hostile).
const sftpMaxPacket = 2 << 20

// sftpParser reconstructs file transfers of one SFTP channel. Requests come
// from the client (feedClient), replies from the server (feedServer).
type sftpParser struct {
	sess    *Session
	channel uint32

	client, server sftpStream
	handles        map[string]*transfer // handle -> transfer
	openReq        map[uint32]*pendingOpen
	readReq        map[uint32]*pendingRead
}

type sftpStream struct {
	buf  []byte
	dead bool
}

type pendingOpen struct {
	filename string
	upload   bool
}

type pendingRead struct {
	handle string
	offset int64
}

func newSFTPParser(sess *Session, channel uint32) *sftpParser {
	return &sftpParser{
		sess:    sess,
		channel: channel,
		handles: make(map[string]*transfer),
		openReq: make(map[uint32]*pendingOpen),
		readReq: make(map[uint32]*pendingRead),
	}
}

// packets pulls complete SFTP packets (uint32 length + payload) from a stream.
func (s *sftpStream) packets(data []byte, fn func(pkt []byte)) {
	if s.dead {
		return
	}
	s.buf = append(s.buf, data...)
	for {
		if len(s.buf) < 4 {
			return
		}
		n := binary.BigEndian.Uint32(s.buf)
		if n == 0 || n > sftpMaxPacket {
			s.dead = true
			s.buf = nil
			return
		}
		if uint64(len(s.buf)) < 4+uint64(n) {
			return
		}
		pkt := s.buf[4 : 4+n]
		s.buf = s.buf[4+n:]
		fn(pkt)
	}
}

func (p *sftpParser) feedClient(data []byte) {
	p.client.packets(data, p.request)
}

func (p *sftpParser) feedServer(data []byte) {
	p.server.packets(data, p.reply)
}

// request handles a client->server SFTP packet.
func (p *sftpParser) request(pkt []byte) {
	if len(pkt) < 5 {
		return
	}
	typ := pkt[0]
	id := binary.BigEndian.Uint32(pkt[1:])
	body := pkt[5:]

	switch typ {
	case fxpOpen:
		name, rest, ok := sftpString(body)
		if !ok || len(rest) < 4 {
			return
		}
		pflags := binary.BigEndian.Uint32(rest)
		p.openReq[id] = &pendingOpen{filename: name, upload: pflags&fxfWrite != 0 || pflags&fxfRead == 0}
	case fxpWrite:
		handle, rest, ok := sftpString(body)
		if !ok || len(rest) < 8 {
			return
		}
		offset := int64(binary.BigEndian.Uint64(rest))
		chunk, _, ok := sftpBytes(rest[8:])
		if !ok {
			return
		}
		if t := p.transferForWrite(handle); t != nil {
			t.write(offset, chunk)
		}
	case fxpRead:
		handle, rest, ok := sftpString(body)
		if !ok || len(rest) < 8 {
			return
		}
		offset := int64(binary.BigEndian.Uint64(rest))
		p.readReq[id] = &pendingRead{handle: handle, offset: offset}
	case fxpClose:
		if handle, _, ok := sftpString(body); ok {
			if t := p.handles[handle]; t != nil {
				t.finish(false)
				delete(p.handles, handle)
			}
		}
	}
}

// reply handles a server->client SFTP packet.
func (p *sftpParser) reply(pkt []byte) {
	if len(pkt) < 5 {
		return
	}
	typ := pkt[0]
	id := binary.BigEndian.Uint32(pkt[1:])
	body := pkt[5:]

	switch typ {
	case fxpHandle:
		open := p.openReq[id]
		delete(p.openReq, id)
		handle, _, ok := sftpString(body)
		if !ok || open == nil {
			return
		}
		dir := "download"
		if open.upload {
			dir = "upload"
		}
		p.handles[handle] = p.sess.startTransfer("sftp", dir, p.channel, open.filename, "")
	case fxpData:
		rd := p.readReq[id]
		delete(p.readReq, id)
		data, _, ok := sftpBytes(body)
		if !ok || rd == nil {
			return
		}
		if t := p.handles[rd.handle]; t != nil {
			t.write(rd.offset, data)
		}
	}
}

// transferForWrite returns the upload transfer of a handle, creating one if
// the OPEN was missed (parser started mid-stream).
func (p *sftpParser) transferForWrite(handle string) *transfer {
	if t := p.handles[handle]; t != nil {
		return t
	}
	t := p.sess.startTransfer("sftp", "upload", p.channel, "", "")
	p.handles[handle] = t
	return t
}

// close ends every transfer still open (channel or session ended).
func (p *sftpParser) close() {
	for h, t := range p.handles {
		t.finish(true)
		delete(p.handles, h)
	}
}

func sftpBytes(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func sftpString(b []byte) (string, []byte, bool) {
	v, rest, ok := sftpBytes(b)
	return string(v), rest, ok
}
