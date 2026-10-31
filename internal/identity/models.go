package identity

import "strings"

// Profile combines a client's static identity with its request model.
// Device state is supplied by Manager; request bodies and transport behavior
// remain outside the model.
type Profile struct {
	Key            string
	Label          string
	ClientName     string
	ClientVersion  string
	DeviceName     string
	DeviceIDLength int
	DeviceIDFormat string
	UserAgent      string
	requests       requestModel
}

type queryIdentityMode uint8

const (
	queryRewriteExisting queryIdentityMode = iota
	queryPromoteAuthToHeaders
	queryDuplicateIdentity
	queryStripResourceIdentity
)

type authorizationStyle struct {
	quoteValues bool
	separator   string
}

// requestModel describes the existing identity placement rules, not a complete
// replica of a client's requests. Zero values preserve the generic policy.
type requestModel struct {
	authorization       authorizationStyle
	apiQuery            queryIdentityMode
	resourceQuery       queryIdentityMode
	promotedAuthHeaders map[string]string
	userRootLanguage    string
	defaultLanguage     string
	userImageToken      string
}

var yambyRequestModel = requestModel{
	authorization: authorizationStyle{separator: ","},
	apiQuery:      queryPromoteAuthToHeaders,
	resourceQuery: queryPromoteAuthToHeaders,
	promotedAuthHeaders: map[string]string{
		"authorization":              "Authorization",
		"xauthorization":             "X-Authorization",
		"xembyauthorization":         "X-Emby-Authorization",
		"xembytoken":                 "X-Emby-Token",
		"xmediabrowserauthorization": "X-MediaBrowser-Authorization",
		"xmediabrowsertoken":         "X-MediaBrowser-Token",
	},
}

// The current Windows and Android policies differ in identity metadata, not in
// request rules. Sharing this value does not infer any unmeasured capabilities.
var hillsRequestModel = requestModel{
	authorization:    authorizationStyle{quoteValues: true, separator: ", "},
	apiQuery:         queryDuplicateIdentity,
	resourceQuery:    queryStripResourceIdentity,
	userRootLanguage: "en-us",
	defaultLanguage:  "zh-cn",
	userImageToken:   "api_key",
}

var Profiles = map[string]Profile{
	"yamby": {
		Key:            "yamby",
		Label:          "Yamby Android",
		ClientName:     "Yamby",
		ClientVersion:  "2.1.0.11",
		DeviceName:     "Android",
		DeviceIDFormat: "uuid",
		UserAgent:      "Yamby/2.1.0.11(Android",
		requests:       yambyRequestModel,
	},
	"hills_android": {
		Key:            "hills_android",
		Label:          "Hills Android",
		ClientName:     "Hills",
		ClientVersion:  "1.10.1",
		DeviceName:     "diting",
		DeviceIDLength: 16,
		UserAgent:      "Hills/1.10.1 (android; 15)",
		requests:       hillsRequestModel,
	},
	"hills_windows": {
		Key:            "hills_windows",
		Label:          "Hills Windows",
		ClientName:     "Hills Windows",
		ClientVersion:  "1.5.5",
		DeviceIDLength: 32,
		UserAgent:      "Hills Windows/1.5.5 (windows; 19041.vb_release.191206-1406)",
		requests:       hillsRequestModel,
	},
}

var ProfileOrder = []string{DefaultProfile, "hills_android", "hills_windows"}

func (style authorizationStyle) format(snap Snapshot) string {
	values := []string{snap.ClientName, snap.DeviceName, snap.DeviceID, snap.ClientVersion}
	keys := []string{"Client", "Device", "DeviceId", "Version"}
	parts := make([]string, len(keys))
	for i, key := range keys {
		value := values[i]
		if style.quoteValues {
			value = `"` + escapeMediaBrowserValue(value) + `"`
		}
		parts[i] = key + "=" + value
	}
	separator := style.separator
	if separator == "" {
		separator = ","
	}
	return "Emby " + strings.Join(parts, separator)
}
