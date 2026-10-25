package audit

import "log/slog"

// Downhook records packets from the client to the backend (keystrokes,
// channel requests). It never returns an error.
func (s *Session) Downhook(msg []byte) error {
	defer recoverHook("downhook")
	if len(msg) == 0 {
		return nil
	}
	switch msg[0] {
	case msgChannelData:
		if id, data, ok := s.clientChanData(msg); ok {
			ev := s.newEvent(EventChanInput)
			ev.Channel = uint32p(id)
			setData(ev, data)
			s.emit(ev)
			s.castAppend(id, "i", data)
		}
	case msgChannelRequest:
		s.channelRequest(msg)
	}
	return nil
}

// Uphook records packets from the backend to the client (terminal output,
// exit status). It never returns an error.
func (s *Session) Uphook(msg []byte) error {
	defer recoverHook("uphook")
	if len(msg) == 0 {
		return nil
	}
	switch msg[0] {
	case msgChannelOpenConfirm:
		// recipient = client id, sender = server id
		rest := msg[1:]
		cli, rest, ok := readUint32(rest)
		if !ok {
			return nil
		}
		srv, _, ok := readUint32(rest)
		if !ok {
			return nil
		}
		s.mu.Lock()
		s.srvToCli[srv] = cli
		s.mu.Unlock()
	case msgChannelData:
		// recipient = client id
		cli, rest, ok := readUint32(msg[1:])
		if !ok {
			return nil
		}
		raw, ok := lastString(rest)
		if !ok {
			return nil
		}
		ev := s.newEvent(EventChanOutput)
		ev.Channel = uint32p(cli)
		ev.Stream = "stdout"
		setData(ev, raw)
		s.emit(ev)
		s.castAppend(cli, "o", raw)
	case msgChannelExtData:
		cli, rest, ok := readUint32(msg[1:])
		if !ok {
			return nil
		}
		_, rest, ok = readUint32(rest) // datatype code (1 = stderr)
		if !ok {
			return nil
		}
		if raw, ok := lastString(rest); ok {
			ev := s.newEvent(EventChanOutput)
			ev.Channel = uint32p(cli)
			ev.Stream = "stderr"
			setData(ev, raw)
			s.emit(ev)
			s.castAppend(cli, "o", raw)
		}
	case msgChannelRequest:
		s.serverChannelRequest(msg)
	}
	return nil
}

// clientChanData parses a channel-data packet seen client->server and returns
// the canonical (client) channel id and the payload.
func (s *Session) clientChanData(msg []byte) (uint32, []byte, bool) {
	srv, rest, ok := readUint32(msg[1:])
	if !ok {
		return 0, nil, false
	}
	raw, ok := lastString(rest)
	if !ok {
		return 0, nil, false
	}
	return s.canonical(srv), raw, true
}

// lastString reads a single ssh string that occupies the rest of b.
func lastString(b []byte) ([]byte, bool) {
	n, rest, ok := readUint32(b)
	if !ok || uint64(n) > uint64(len(rest)) {
		return nil, false
	}
	return rest[:n], true
}

func (s *Session) canonical(serverID uint32) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.srvToCli[serverID]; ok {
		return c
	}
	return serverID
}

func (s *Session) chanState(id uint32) *chanState {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.chans[id]
	if c == nil {
		c = &chanState{}
		s.chans[id] = c
	}
	return c
}

// channelRequest parses a client->server channel request (98).
func (s *Session) channelRequest(msg []byte) {
	srv, rest, ok := readUint32(msg[1:])
	if !ok {
		return
	}
	reqType, rest, ok := readString(rest)
	if !ok {
		return
	}
	_, rest, ok = readBool(rest) // want_reply
	if !ok {
		return
	}
	id := s.canonical(srv)

	switch reqType {
	case "pty-req":
		term, r, ok := readString(rest)
		if !ok {
			break
		}
		width, r, _ := readUint32(r)
		height, _, _ := readUint32(r)
		c := s.chanState(id)
		s.mu.Lock()
		c.term, c.width, c.height = term, width, height
		s.mu.Unlock()
		ev := s.newEvent(EventSize)
		ev.Channel, ev.Width, ev.Height = uint32p(id), width, height
		s.emit(ev)
	case "env":
		name, r, ok := readString(rest)
		if !ok {
			break
		}
		value, _, _ := readString(r)
		s.mu.Lock()
		s.envOnly[name] = value
		s.mu.Unlock()
		ev := s.newEvent(EventVar)
		ev.Channel, ev.Name, ev.Value = uint32p(id), name, value
		s.emit(ev)
	case "shell":
		s.openCast(id)
		s.channelRequestEvent(id, reqType, "")
	case "exec":
		command, _, _ := readString(rest)
		s.openCast(id)
		ev := s.newEvent(EventCommand)
		ev.Channel, ev.Input = uint32p(id), command
		s.emit(ev)
		s.channelRequestEvent(id, reqType, command)
	case "window-change":
		width, r, ok := readUint32(rest)
		if !ok {
			break
		}
		height, _, _ := readUint32(r)
		s.mu.Lock()
		if c := s.chans[id]; c != nil {
			c.width, c.height = width, height
		}
		s.mu.Unlock()
		ev := s.newEvent(EventSize)
		ev.Channel, ev.Width, ev.Height = uint32p(id), width, height
		s.emit(ev)
		s.castResize(id, width, height)
	default:
		s.channelRequestEvent(id, reqType, "")
	}
}

func (s *Session) channelRequestEvent(id uint32, reqType, value string) {
	ev := s.newEvent(EventChanRequest)
	ev.Channel, ev.RequestType = uint32p(id), reqType
	if value != "" {
		ev.Value = value
	}
	s.emit(ev)
}

// serverChannelRequest parses a server->client channel request (98):
// exit-status and exit-signal.
func (s *Session) serverChannelRequest(msg []byte) {
	cli, rest, ok := readUint32(msg[1:])
	if !ok {
		return
	}
	reqType, rest, ok := readString(rest)
	if !ok {
		return
	}
	_, rest, ok = readBool(rest)
	if !ok {
		return
	}
	switch reqType {
	case "exit-status":
		code, _, ok := readUint32(rest)
		if !ok {
			return
		}
		ev := s.newEvent(EventChanExit)
		ev.Channel, ev.ExitStatus = uint32p(cli), uint32p(code)
		s.emit(ev)
	case "exit-signal":
		sig, _, ok := readString(rest)
		if !ok {
			return
		}
		ev := s.newEvent(EventChanExit)
		ev.Channel, ev.ExitSignal = uint32p(cli), sig
		s.emit(ev)
	}
}

func recoverHook(which string) {
	if r := recover(); r != nil {
		// an audit panic must never reach the pipe
		slog.Error("audit hook recovered from panic", "hook", which, "panic", r)
	}
}
