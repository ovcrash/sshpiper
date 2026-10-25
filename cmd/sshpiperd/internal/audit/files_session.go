package audit

// Per-channel file-transfer parsers, driven by the session hooks.

type fileChannel struct {
	scp  *scpParser
	sftp *sftpParser
}

func (s *Session) fileChannel(id uint32) *fileChannel {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fileChans == nil {
		s.fileChans = make(map[uint32]*fileChannel)
	}
	fc := s.fileChans[id]
	if fc == nil {
		fc = &fileChannel{}
		s.fileChans[id] = fc
	}
	return fc
}

// startSCP begins an scp transfer on a channel if the exec command is one.
func (s *Session) startSCP(id uint32, command string) {
	p := newSCPParser(s, id, command)
	if p == nil {
		return
	}
	s.fileChannel(id).scp = p
}

// startSFTP begins SFTP parsing on a channel.
func (s *Session) startSFTP(id uint32) {
	s.fileChannel(id).sftp = newSFTPParser(s, id)
}

// feedFileClient feeds client->server channel data to the channel's parser.
func (s *Session) feedFileClient(id uint32, data []byte) {
	s.mu.Lock()
	fc := s.fileChans[id]
	s.mu.Unlock()
	if fc == nil {
		return
	}
	if fc.scp != nil && fc.scp.dir == "upload" {
		fc.scp.feed(data)
	}
	if fc.sftp != nil {
		fc.sftp.feedClient(data)
	}
}

// feedFileServer feeds server->client channel data to the channel's parser.
func (s *Session) feedFileServer(id uint32, data []byte) {
	s.mu.Lock()
	fc := s.fileChans[id]
	s.mu.Unlock()
	if fc == nil {
		return
	}
	if fc.scp != nil && fc.scp.dir == "download" {
		fc.scp.feed(data)
	}
	if fc.sftp != nil {
		fc.sftp.feedServer(data)
	}
}

// closeFileChannel finishes the transfers of one channel.
func (s *Session) closeFileChannel(id uint32) {
	s.mu.Lock()
	fc := s.fileChans[id]
	delete(s.fileChans, id)
	s.mu.Unlock()
	finishFileChannel(fc)
}

// closeAllFiles finishes every remaining transfer (session ended).
func (s *Session) closeAllFiles() {
	s.mu.Lock()
	chans := s.fileChans
	s.fileChans = nil
	s.mu.Unlock()
	for _, fc := range chans {
		finishFileChannel(fc)
	}
}

func finishFileChannel(fc *fileChannel) {
	if fc == nil {
		return
	}
	if fc.scp != nil {
		fc.scp.close()
	}
	if fc.sftp != nil {
		fc.sftp.close()
	}
}
