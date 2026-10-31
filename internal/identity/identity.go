package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"embyproxy/internal/storage"
)

const identityKey = "system:upstream_identity"
const DefaultProfile = "yamby"

// deviceIDContext versions the device ID derivation. Changing the derivation
// changes every impersonated device and invalidates tokens on upstreams that
// bind tokens to devices, so it must never change silently.
const deviceIDContext = "embyproxy/device/v1"

const desktopNameAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Snapshot is the impersonated identity used for one request.
type Snapshot struct {
	Profile       string `json:"profile"`
	Label         string `json:"label"`
	ClientName    string `json:"clientName"`
	ClientVersion string `json:"clientVersion"`
	DeviceName    string `json:"deviceName"`
	DeviceID      string `json:"deviceId"`
	UserAgent     string `json:"userAgent"`
	// SourceDeviceID is the normalized device ID declared by the source client.
	SourceDeviceID string `json:"-"`
}

type deviceState struct {
	DeviceName string `json:"deviceName"`
	DeviceID   string `json:"deviceId"`
}

type persisted struct {
	ClientName    string                 `json:"clientName"`
	ClientVersion string                 `json:"clientVersion"`
	UserAgent     string                 `json:"userAgent"`
	Profiles      map[string]deviceState `json:"profiles"`
}

// Manager owns the persisted per-profile device state and derives the
// impersonated identity of each source device.
//
// Requests normally derive IDs from their source device (Resolve). Nodes may
// opt into the persisted per-profile shared identity instead (ResolveShared).
type Manager struct {
	store       *storage.Store
	mu          sync.Mutex
	profiles    map[string]deviceState
	initialized bool

	knownMu      sync.RWMutex
	knownDevices map[string]*knownSourceDevices
}

func NewManager(store *storage.Store) *Manager {
	return &Manager{store: store, profiles: map[string]deviceState{}}
}

func (m *Manager) Init(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var saved persisted
	_, _ = m.store.KV().GetJSON(ctx, identityKey, &saved)
	m.profiles = normalizeSavedProfiles(saved.Profiles)
	m.initialized = true
	current := m.persistedLocked()
	if !samePersisted(saved, current) {
		return m.store.KV().Put(ctx, identityKey, current)
	}
	return nil
}

// Resolve returns the impersonated identity for a source device. The device
// ID depends only on the profile and the source device ID, so a device keeps
// the same impersonated ID across nodes, routes, and proxy instances. Without
// a source device ID the snapshot carries no device identity and requests
// keep only their tokens.
func (m *Manager) Resolve(profile, sourceDeviceID string) Snapshot {
	selected := GetProfile(profile)
	snap := Snapshot{
		Profile:       selected.Key,
		Label:         selected.Label,
		ClientName:    selected.ClientName,
		ClientVersion: selected.ClientVersion,
		DeviceName:    strings.TrimSpace(selected.DeviceName),
		UserAgent:     selected.UserAgent,
	}
	if snap.DeviceName == "" {
		snap.DeviceName = m.savedDeviceName(selected.Key)
	}
	source := normalizeSourceDeviceID(sourceDeviceID)
	if source == "" {
		return snap
	}
	sum := deviceHash(selected.Key, source)
	snap.SourceDeviceID = source
	snap.DeviceID = formatDeviceID(selected, sum)
	if snap.DeviceName == "" {
		snap.DeviceName = hillsWindowsDeviceName(sum)
	}
	return snap
}

// ResolveShared uses the persisted per-profile device identity instead of the
// v1 source-derived ID. Missing source identities remain token-only. SourceDeviceID
// is retained so stream URLs can replace only confirmed source IDs.
func (m *Manager) ResolveShared(profile, sourceDeviceID string) Snapshot {
	snap := m.Resolve(profile, sourceDeviceID)
	if snap.SourceDeviceID == "" {
		return snap
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureLocked()
	state := m.deviceStateLocked(snap.Profile)
	snap.DeviceID = state.DeviceID
	snap.DeviceName = state.DeviceName
	if snap.DeviceName == "" {
		snap.DeviceName = hillsWindowsDeviceName(deviceHash(snap.Profile, state.DeviceID))
	}
	return snap
}

func NormalizeProfile(value string) string {
	key := strings.ToLower(strings.TrimSpace(value))
	if _, ok := Profiles[key]; ok {
		return key
	}
	return DefaultProfile
}

func GetProfile(value string) Profile {
	return Profiles[NormalizeProfile(value)]
}

func ProfileKeys() []string {
	seen := map[string]bool{}
	keys := make([]string, 0, len(Profiles))
	for _, key := range ProfileOrder {
		if _, ok := Profiles[key]; ok && !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	extra := make([]string, 0, len(Profiles)-len(keys))
	for key := range Profiles {
		if !seen[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	return append(keys, extra...)
}

func normalizeSourceDeviceID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func deviceHash(profile, source string) [sha256.Size]byte {
	return sha256.Sum256([]byte(deviceIDContext + "\x00" + profile + "\x00" + source))
}

func formatDeviceID(profile Profile, sum [sha256.Size]byte) string {
	switch strings.ToLower(strings.TrimSpace(profile.DeviceIDFormat)) {
	case "uuid":
		return uuidV4(sum[:16])
	default:
		length := profile.DeviceIDLength
		if length <= 0 {
			length = 32
		}
		if length > 2*len(sum) {
			length = 2 * len(sum)
		}
		return hex.EncodeToString(sum[:])[:length]
	}
}

// hillsWindowsDeviceName follows the default Windows computer name shape:
// DESKTOP- followed by seven uppercase letters or digits.
func hillsWindowsDeviceName(sum [sha256.Size]byte) string {
	name := make([]byte, 7)
	for i := range name {
		name[i] = desktopNameAlphabet[int(sum[16+i])%len(desktopNameAlphabet)]
	}
	return "DESKTOP-" + string(name)
}

func (m *Manager) savedDeviceName(profile string) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureLocked()
	return m.deviceStateLocked(profile).DeviceName
}

func (m *Manager) persistedLocked() persisted {
	selected := GetProfile(DefaultProfile)
	profiles := map[string]deviceState{}
	for key := range Profiles {
		profiles[key] = m.deviceStateLocked(key)
	}
	return persisted{
		ClientName:    selected.ClientName,
		ClientVersion: selected.ClientVersion,
		UserAgent:     selected.UserAgent,
		Profiles:      profiles,
	}
}

func (m *Manager) ensureLocked() {
	if m.initialized && m.profiles != nil {
		return
	}
	m.profiles = normalizeSavedProfiles(m.profiles)
	m.initialized = true
}

func (m *Manager) deviceStateLocked(profile string) deviceState {
	selected := GetProfile(profile)
	if m.profiles == nil {
		m.profiles = map[string]deviceState{}
	}
	state := normalizeDeviceState(selected, m.profiles[selected.Key])
	m.profiles[selected.Key] = state
	return state
}

func normalizeSavedProfiles(saved map[string]deviceState) map[string]deviceState {
	out := map[string]deviceState{}
	for key := range Profiles {
		out[key] = normalizeDeviceState(Profiles[key], saved[key])
	}
	return out
}

func normalizeDeviceState(profile Profile, saved deviceState) deviceState {
	name := strings.TrimSpace(profile.DeviceName)
	if name == "" {
		// A name saved by an earlier release stays in use for every device.
		// New deployments save none and derive the name per source device.
		name = strings.TrimSpace(saved.DeviceName)
	}
	deviceID := strings.ToLower(strings.TrimSpace(saved.DeviceID))
	if !validDeviceID(profile, deviceID) {
		deviceID = randomDeviceID(profile)
	}
	return deviceState{DeviceName: name, DeviceID: deviceID}
}

func samePersisted(a, b persisted) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func isHexLength(value string, length int) bool {
	if length <= 0 {
		length = 32
	}
	if len(value) != length {
		return false
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return false
	}
	return true
}

func validDeviceID(profile Profile, value string) bool {
	switch strings.ToLower(strings.TrimSpace(profile.DeviceIDFormat)) {
	case "uuid":
		return isUUID(value)
	default:
		return isHexLength(value, profile.DeviceIDLength)
	}
}

func randomDeviceID(profile Profile) string {
	switch strings.ToLower(strings.TrimSpace(profile.DeviceIDFormat)) {
	case "uuid":
		return randomUUID()
	default:
		return randomHex(profile.DeviceIDLength)
	}
}

func randomHex(length int) string {
	if length <= 0 {
		length = 32
	}
	buf := make([]byte, (length+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", length)
	}
	return hex.EncodeToString(buf)[:length]
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, ch := range value {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
				continue
			}
			return false
		}
	}
	return true
}

func randomUUID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	return uuidV4(buf)
}

// uuidV4 formats the first 16 bytes of b as a version 4, variant 1 UUID.
func uuidV4(b []byte) string {
	buf := append([]byte(nil), b[:16]...)
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	hexed := hex.EncodeToString(buf)
	return hexed[:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:]
}
