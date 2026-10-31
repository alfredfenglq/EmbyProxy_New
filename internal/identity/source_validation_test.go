package identity

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSourceDeviceIDRejectsInvalidQueryEncoding(t *testing.T) {
	for _, extract := range []struct {
		name string
		fn   func(http.Header, *url.URL) (string, error)
	}{
		{"http", SourceDeviceID},
		{"websocket", WebSocketSourceDeviceID},
	} {
		for _, query := range []string{
			"X-Emby-Device-Id=abc%ZZ",
			"X-Emby-Device-Id=abc%",
			"X-Emby-Device-Id=abc%2",
			"X-Emby-Device%ZZId=abc",
			"X-Emby-Authorization=Emby%20DeviceId%3Dabc%ZZ",
			"deviceId=abc%ZZ",
			"X-Emby-Device-Id=valid&X-Emby-Device-Id=bad%ZZ",
			"X-Emby-Device-Id=valid&tag=bad%ZZ",
		} {
			for _, withHeader := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/header=%t", extract.name, query, withHeader), func(t *testing.T) {
					headers := http.Header{}
					if withHeader {
						headers.Set("X-Emby-Authorization", `Emby DeviceId="valid-header"`)
					}
					u := &url.URL{Path: "/Items", RawQuery: query}
					source, err := extract.fn(headers, u)
					var escapeErr url.EscapeError
					if source != "" || !errors.Is(err, ErrInvalidQueryEncoding) || !errors.As(err, &escapeErr) {
						t.Fatalf("source=%q, error=%v; want empty source and query decoding error", source, err)
					}
					if u.RawQuery != query {
						t.Fatal("source extraction mutated the query")
					}
				})
			}
		}
	}
}

func TestSourceDeviceIDRejectsUnescapedSemicolons(t *testing.T) {
	for _, query := range []string{"X-Emby-Device-Id=a;b", "X-Emby-Device-Id=valid&tag=a;b", "deviceId=a;b"} {
		u := &url.URL{RawQuery: query}
		for _, extract := range []func(http.Header, *url.URL) (string, error){SourceDeviceID, WebSocketSourceDeviceID} {
			id, err := extract(http.Header{"X-Emby-Authorization": {`Emby DeviceId="valid"`}}, u)
			if id != "" || !errors.Is(err, ErrInvalidQueryEncoding) {
				t.Fatalf("query=%q: source=%q, error=%v; want invalid query error", query, id, err)
			}
		}
	}
}

func TestSourceDeviceIDDecodesExactlyOnce(t *testing.T) {
	for _, tt := range []struct{ query, want string }{
		{"X-Emby-Device-Id=abc%25ZZ", "abc%ZZ"},
		{"X-Emby-Device-Id=abc%2525", "abc%25"},
		{"X-Emby-Device-Id=a%2Bb", "a+b"},
		{"X-Emby-Device-Id=a%3Bb", "a;b"},
		{"X-Emby-Device-Id=a+b", "a b"},
		{"X-Emby-Authorization=" + url.QueryEscape(`Emby DeviceId="abc%ZZ"`), "abc%ZZ"},
	} {
		t.Run(tt.query, func(t *testing.T) {
			u := &url.URL{RawQuery: tt.query}
			for _, extract := range []func(http.Header, *url.URL) (string, error){SourceDeviceID, WebSocketSourceDeviceID} {
				got, err := extract(http.Header{}, u)
				if err != nil || got != tt.want {
					t.Fatalf("source=%q, error=%v; want %q, nil", got, err, tt.want)
				}
			}
		})
	}
}

func TestResourceNormalizationRejectsInvalidQueryBeforeMutation(t *testing.T) {
	for _, kind := range []string{ResourceImage, ResourceStream, ResourceSmartSTRM, ResourcePublicInfo} {
		t.Run(kind, func(t *testing.T) {
			u := &url.URL{Path: "/Videos/1/stream.mp4", RawQuery: "DeviceId=abc%ZZ&api_key=token"}
			before := *u
			headers := http.Header{"X-Emby-Token": {"token"}, "X-Emby-Authorization": {`Emby DeviceId="source"`}}
			originalHeaders := headers.Clone()
			err := NormalizeImpersonatedResource(u, headers, NewManager(nil).Resolve("hills_android", "source"), kind)
			if !errors.Is(err, ErrInvalidQueryEncoding) {
				t.Fatalf("error=%v, want query decoding error", err)
			}
			if !reflect.DeepEqual(*u, before) || !reflect.DeepEqual(headers, originalHeaders) {
				t.Fatal("invalid query caused partial identity rewriting")
			}
		})
	}
}

func TestStreamDeviceIDIndependentOfRequestHistory(t *testing.T) {
	for _, profile := range ProfileKeys() {
		t.Run(profile, func(t *testing.T) {
			const source = "source-device"
			fresh := NewManager(nil)
			warm := NewManager(nil)
			derived := warm.Resolve(profile, source).DeviceID
			busy := NewManager(nil)
			busy.Resolve(profile, source)
			// Resolve must keep no per-source state; exercise many distinct sources.
			for i := 0; i < 1100; i++ {
				busy.Resolve(profile, fmt.Sprintf("other-device-%d", i))
			}
			for _, manager := range []*Manager{fresh, warm, busy, NewManager(nil)} {
				for _, declared := range []string{"", source} {
					snap := manager.Resolve(profile, declared)
					for _, value := range []string{source, derived, "server-issued-value"} {
						want := value
						if value == source && declared == source {
							want = derived
						}
						u := &url.URL{Path: "/Videos/1/stream.mp4", RawQuery: "deviceId=" + value + "&api_key=t"}
						// Repeating the rewrite must not double-hash an issued ID.
						for repeat := 0; repeat < 2; repeat++ {
							if err := NormalizeImpersonatedResource(u, http.Header{}, snap, ResourceStream); err != nil {
								t.Fatal(err)
							}
							if got := u.Query().Get("deviceId"); got != want {
								t.Fatalf("declared=%q, URL device=%q, got=%q, want=%q", declared, value, got, want)
							}
						}
					}
				}
			}
		})
	}
}

func TestResolveDoesNotRetainLargeSourceIDs(t *testing.T) {
	manager := NewManager(nil)
	manager.Resolve("hills_windows", "initial")
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 32; i++ {
		manager.Resolve("hills_windows", fmt.Sprintf("%d-", i)+strings.Repeat("a", 512*1024))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	// Resolve must not retain source IDs. Allow ample allocator noise, but not
	// retention proportional to the total source input (16 MiB here).
	if growth := int64(after.HeapAlloc) - int64(before.HeapAlloc); growth > 8*1024*1024 {
		t.Fatalf("retained heap grew by %d bytes after resolving disposable source IDs", growth)
	}
	runtime.KeepAlive(manager)
}
