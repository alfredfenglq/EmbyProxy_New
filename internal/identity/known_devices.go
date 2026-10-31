package identity

import (
	"net/url"
	"strings"
)

type knownSourceDevices struct {
	sources map[string]bool
	derived map[string]bool
}

// RememberSourceDevice records a source explicitly declared by a successful
// node request. Multiple devices can share a token; tokens are not device keys.
// Records live only in this manager's memory and must be learned again after
// a restart. The node key excludes the upstream line and impersonation profile.
func (m *Manager) RememberSourceDevice(node, source string) {
	node = strings.ToLower(strings.TrimSpace(node))
	source = normalizeSourceDeviceID(source)
	if m == nil || source == "" || node == "" {
		return
	}
	m.knownMu.Lock()
	defer m.knownMu.Unlock()
	if m.knownDevices == nil {
		m.knownDevices = map[string]*knownSourceDevices{}
	}
	known := m.knownDevices[node]
	if known == nil {
		known = &knownSourceDevices{
			sources: map[string]bool{},
			derived: map[string]bool{},
		}
		m.knownDevices[node] = known
	}
	if known.sources[source] {
		return
	}
	known.sources[source] = true
	for _, profile := range Profiles {
		known.derived[formatDeviceID(profile, deviceHash(profile.Key, source))] = true
	}
}

// KnownStreamSource returns a previously declared source matching the first
// nonblank bare DeviceId in a stream URL. Callers must use this only for node
// streams without an explicit source identity, not raw/external URLs or APIs.
// Derived and persisted shared IDs take precedence over source matches to
// prevent double hashing, including IDs from a different identity profile.
func (m *Manager) KnownStreamSource(node string, u *url.URL) (string, error) {
	params, err := orderedQueryParams(u)
	if err != nil {
		return "", err
	}
	_, value := firstQueryParam(params, "deviceid")
	candidate := normalizeSourceDeviceID(value)
	node = strings.ToLower(strings.TrimSpace(node))
	if m == nil || candidate == "" || node == "" {
		return "", nil
	}
	// A shared ID may have been echoed by a client as its declared source.
	// Preserve it even after the node switches back to per-source identities.
	m.mu.Lock()
	for _, state := range m.profiles {
		if candidate == normalizeSourceDeviceID(state.DeviceID) {
			m.mu.Unlock()
			return "", nil
		}
	}
	m.mu.Unlock()
	m.knownMu.RLock()
	defer m.knownMu.RUnlock()
	known := m.knownDevices[node]
	if known == nil || known.derived[candidate] || !known.sources[candidate] {
		return "", nil
	}
	return candidate, nil
}
