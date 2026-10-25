package audit

import "fmt"

// attempt is the last authentication attempt seen for a session, kept so the
// verdict (decided by the backend) can be logged with its details.
type attempt struct {
	method      string
	password    string
	fingerprint string
	keyLine     string
	keyType     string
	username    string
}

// SetPasswordAttempt records a password attempt (no event yet: the backend
// decides the verdict).
func (s *Session) SetPasswordAttempt(username, password string) {
	s.mu.Lock()
	s.lastAttempt = attempt{method: "password", username: username, password: password}
	s.mu.Unlock()
}

// SetKeyAttempt records a public key attempt and emits piper.client.fingerprint.
func (s *Session) SetKeyAttempt(username, fingerprint, keyLine, keyType string) {
	s.mu.Lock()
	s.lastAttempt = attempt{method: "publickey", username: username, fingerprint: fingerprint, keyLine: keyLine, keyType: keyType}
	s.mu.Unlock()

	ev := s.newEvent(EventFingerprint)
	ev.Username, ev.Fingerprint, ev.Key, ev.KeyType = username, fingerprint, keyLine, keyType
	s.emit(ev)
}

// SetOfferedMethods records the methods the backend offered (from the
// plugin's NextAuthMethods), used as allowed_methods on a failure.
func (s *Session) SetOfferedMethods(methods []string) {
	s.mu.Lock()
	s.offered = append([]string(nil), methods...)
	s.mu.Unlock()
}

// LoginFailed emits piper.login.failed for the last attempt.
func (s *Session) LoginFailed() {
	s.mu.Lock()
	a, offered := s.lastAttempt, append([]string(nil), s.offered...)
	s.mu.Unlock()
	s.emitLogin(EventLoginFailed, a, offered, "failed")
}

// LoginSuccess emits piper.login.success for the last attempt.
func (s *Session) LoginSuccess() {
	s.mu.Lock()
	a := s.lastAttempt
	s.loggedSuccess = true
	s.mu.Unlock()
	s.emitLogin(EventLoginOK, a, nil, "succeeded")
}

// HadLoginSuccess reports whether a success was already emitted.
func (s *Session) HadLoginSuccess() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loggedSuccess
}

func (s *Session) emitLogin(id string, a attempt, offered []string, verb string) {
	if a.method == "" {
		return
	}
	ev := s.newEvent(id)
	ev.Username, ev.Method = a.username, a.method
	ev.Message = fmt.Sprintf("login attempt [%s] %s", a.username, verb)
	switch a.method {
	case "password":
		ev.Password = a.password
	case "publickey":
		ev.Fingerprint = a.fingerprint
	}
	ev.AllowedMethods = offered
	s.emit(ev)
}
