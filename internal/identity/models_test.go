package identity

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestClientModelsDescribeExistingRules(t *testing.T) {
	for _, tt := range []struct {
		profile, client, userAgent, imageToken string
		apiQuery, resourceQuery                queryIdentityMode
		quoteValues                            bool
	}{
		{DefaultProfile, "Yamby", "Yamby/2.1.0.11(Android", "", queryPromoteAuthToHeaders, queryPromoteAuthToHeaders, false},
		{"hills_android", "Hills", "Hills/1.10.1 (android; 15)", "api_key", queryDuplicateIdentity, queryStripResourceIdentity, true},
		{"hills_windows", "Hills Windows", "Hills Windows/1.5.5 (windows; 19041.vb_release.191206-1406)", "api_key", queryDuplicateIdentity, queryStripResourceIdentity, true},
	} {
		t.Run(tt.profile, func(t *testing.T) {
			profile := GetProfile(tt.profile)
			model := profile.requests
			if profile.ClientName != tt.client || profile.UserAgent != tt.userAgent {
				t.Fatalf("client identity changed: %+v", profile)
			}
			if model.apiQuery != tt.apiQuery || model.resourceQuery != tt.resourceQuery || model.userImageToken != tt.imageToken || model.authorization.quoteValues != tt.quoteValues {
				t.Fatalf("request rules = %+v", model)
			}
		})
	}
}

func TestRequestModelDrivesProcessingInsteadOfProfileName(t *testing.T) {
	const key = "test_request_model"
	profile := GetProfile(DefaultProfile)
	profile.Key = key
	// Keep Yamby's metadata but assign the shared Hills rules. Processing must
	// follow the model, not checks for a particular client name or profile key.
	profile.requests = hillsRequestModel
	Profiles[key] = profile
	t.Cleanup(func() { delete(Profiles, key) })
	snap := testSnapshot(key)
	headers := http.Header{"X-Emby-Authorization": {testSourceEmbyAuth}, "X-Emby-Token": {"token"}}
	u, err := url.Parse("https://example.test/Users/account?tag=v1")
	if err != nil {
		t.Fatal(err)
	}
	ApplyToURL(u, headers, testSnapshot(key))
	ApplyToHeaders(headers, testSnapshot(key))
	wantAuth := `Emby Client="Yamby", Device="Android", DeviceId="` + snap.DeviceID + `", Version="2.1.0.11"`
	if headers.Get("X-Emby-Authorization") != wantAuth || u.Query().Get("X-Emby-Authorization") != wantAuth || u.Query().Get("X-Emby-Token") != "token" || u.Query().Get("X-Emby-Language") != "en-us" {
		t.Fatalf("API ignored request model: headers=%v, URL=%s", headers, u)
	}
	if u.Query().Get("tag") != "v1" {
		t.Fatalf("business query changed: %s", u)
	}

	stream, err := url.Parse("https://example.test/Videos/item/stream.mp4?DeviceId=" + testSourceDeviceID + "&X-Emby-Token=server-token&Static=false")
	if err != nil {
		t.Fatal(err)
	}
	if err := NormalizeImpersonatedResource(stream, headers, testSnapshot(key), ResourceStream); err != nil {
		t.Fatal(err)
	}
	if stream.Query().Has("api_key") || stream.Query().Get("X-Emby-Token") != "server-token" || stream.Query().Get("DeviceId") != snap.DeviceID || stream.Query().Get("Static") != "false" {
		t.Fatalf("stream ignored request model: %s", stream)
	}

	resource, err := url.Parse("https://example.test/Users/account/Images/Primary?X-Emby-Authorization=" + url.QueryEscape(testSourceEmbyAuth))
	if err != nil {
		t.Fatal(err)
	}
	headers = http.Header{}
	ApplyToResourceURL(resource, headers, testSnapshot(key))
	if resource.Query().Has("X-Emby-Authorization") || headers.Get("X-Emby-Authorization") != wantAuth {
		t.Fatalf("resource query ignored request model: %s, %v", resource, headers)
	}
	if err := NormalizeImpersonatedResource(resource, http.Header{"X-Emby-Token": {"avatar-token"}}, testSnapshot(key), ResourceImage); err != nil {
		t.Fatal(err)
	}
	if resource.Query().Get("api_key") != "avatar-token" {
		t.Fatalf("user image ignored request model: %s", resource)
	}
}

func TestAuthorizationModelPreservesStandaloneSnapshotFallback(t *testing.T) {
	for _, tt := range []struct {
		name, profile, client string
		quoted                bool
	}{
		{"legacy yamby", "", " YAMBY ", false},
		{"legacy hills", "", "Hills", true},
		{"legacy unknown client", "", "Other", true},
		{"unknown profile", "unknown", "Other", false},
		{"normalized profile", " HILLS_WINDOWS ", "Other", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			snap := Snapshot{Profile: tt.profile, ClientName: tt.client, DeviceName: `PC"\`, DeviceID: "device", ClientVersion: "1"}
			got := RewriteMediaBrowserAuthorization(testSourceEmbyAuth, snap)
			want := "Emby Client=" + tt.client + `,Device=PC"\,DeviceId=device,Version=1`
			if tt.quoted {
				want = `Emby Client="` + tt.client + `", Device="PC\"\\", DeviceId="device", Version="1"`
			}
			if got != want {
				t.Fatalf("authorization = %q, want %q", got, want)
			}
			if strings.Contains(got, "UserId=") || strings.Contains(got, "Token=") {
				t.Fatalf("source authorization fields leaked: %s", got)
			}
		})
	}
}
