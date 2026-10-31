package identity

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestRequestIdentityPreservesExistingAPIPolicy(t *testing.T) {
	for _, profile := range ProfileOrder {
		for _, path := range []string{"/Users/AuthenticateByName", "/System/Info/Public", "/Sessions/Playing/Progress"} {
			t.Run(profile+path+"/without authorization", func(t *testing.T) {
				u, err := url.Parse("https://example.test" + path + "?api_key=api-token&DeviceId=source-device&DeviceName=source-name&UserId=account&tag=v1")
				if err != nil {
					t.Fatal(err)
				}
				headers := http.Header{"X-Emby-Token": {"header-token"}}
				ApplyToURL(u, headers, testSnapshot(profile))
				ApplyToHeaders(headers, testSnapshot(profile))
				wantQuery := url.Values{"api_key": {"api-token"}, "UserId": {"account"}, "tag": {"v1"}}
				if profile != DefaultProfile {
					wantQuery.Set("DeviceName", "source-name")
				}
				if !reflect.DeepEqual(u.Query(), wantQuery) {
					t.Fatalf("query = %v, want %v", u.Query(), wantQuery)
				}
				if headers.Get("X-Emby-Authorization") != "" || headers.Get("X-Emby-Token") != "header-token" {
					t.Fatalf("headers = %v; existing policy must not invent authorization or strip the token", headers)
				}
			})

			t.Run(profile+path+"/query authorization", func(t *testing.T) {
				query := url.Values{"X-Emby-Authorization": {testSourceEmbyTokenAuth}, "UserId": {"account"}, "reqformat": {"source-format"}, "DeviceName": {"source-name"}}
				u, err := url.Parse("https://example.test" + path + "?" + query.Encode())
				if err != nil {
					t.Fatal(err)
				}
				headers := http.Header{}
				ApplyToURL(u, headers, testSnapshot(profile))
				if profile == DefaultProfile && headers.Get("X-Emby-Authorization") != testSourceEmbyTokenAuth {
					t.Fatalf("query authorization must be promoted before header rewriting: %v", headers)
				}
				ApplyToHeaders(headers, testSnapshot(profile))
				if headers.Get("X-Emby-Token") != "source-token" || headers.Get("X-Emby-Authorization") == "" {
					t.Fatalf("existing login/public/lifecycle authentication changed: %v", headers)
				}
				q := u.Query()
				if q.Get("UserId") != "account" || q.Get("reqformat") != "source-format" {
					t.Fatalf("business query changed: %v", q)
				}
				if profile == DefaultProfile {
					if q.Has("X-Emby-Authorization") || q.Has("DeviceName") {
						t.Fatalf("Yamby source query identity retained: %v", q)
					}
				} else if q.Get("X-Emby-Authorization") != headers.Get("X-Emby-Authorization") || q.Get("DeviceName") != "source-name" {
					t.Fatalf("Hills query identity or bare DeviceName changed: %v", q)
				}
			})
		}
	}
}

func TestRequestIdentityPreservesExistingResourcePolicy(t *testing.T) {
	for _, tt := range []struct {
		name, profile, path, kind, query, tokenKey, token string
	}{
		{"yamby image retains api key", DefaultProfile, "/Items/item/Images/Primary", ResourceImage, "api_key=query-token", "api_key", "query-token"},
		{"hills item image does not add api key", "hills_android", "/Items/item/Images/Primary", ResourceImage, "", "api_key", ""},
		{"hills user image adds api key", "hills_windows", "/Users/account/Images/Primary", ResourceImage, "", "api_key", "header-token"},
		{"windows original keeps api key", "hills_windows", "/Videos/item/original.mp4", ResourceStream, "api_key=query-token&Static=false", "api_key", "query-token"},
		{"android stream adds api key", "hills_android", "/Videos/item/original.mkv", ResourceStream, "", "api_key", "header-token"},
		{"yamby stream uses api key", DefaultProfile, "/Videos/item/stream.mp4", ResourceStream, "Static=true", "api_key", "header-token"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse("https://example.test" + tt.path + "?" + tt.query)
			if err != nil {
				t.Fatal(err)
			}
			before := u.Query()
			headers := http.Header{"X-Emby-Token": {"header-token"}, "X-Emby-Authorization": {testSourceEmbyAuth}}
			if err := NormalizeImpersonatedResource(u, headers, testSnapshot(tt.profile), tt.kind); err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if got := q.Get(tt.tokenKey); got != tt.token {
				t.Fatalf("%s = %q, want %q", tt.tokenKey, got, tt.token)
			}
			if tt.kind == ResourceStream && q.Has("X-Emby-Token") {
				t.Fatalf("stream invented query X-Emby-Token: %v", q)
			}
			if !reflect.DeepEqual(q["Static"], before["Static"]) {
				t.Fatalf("Static changed: %v", q)
			}
			if headers.Get("X-Emby-Token") != "" || headers.Get("X-Emby-Authorization") != "" {
				t.Fatalf("resource identity headers retained: %v", headers)
			}
		})
	}
}
