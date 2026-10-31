package identity

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var embyAuthorizationDeviceIDRE = regexp.MustCompile(`(?i)^(?:MediaBrowser|Emby)(?:\s|$).*?\bDeviceId\s*=\s*("[^"]*"|[^,\s]+)`)

// ErrInvalidQueryEncoding identifies invalid query encoding. Callers must
// reject it rather than deriving an identity from raw input.
var ErrInvalidQueryEncoding = errors.New("invalid query encoding")

// SourceDeviceID returns the device ID that the source client declares in its
// identity fields, in priority order: Emby authorization headers, standalone
// device ID headers, query authorization, then standalone device ID query
// parameters. A bare DeviceId query parameter is not an identity field: in
// stream URLs its provenance is unknown without a declared source identity.
// Query decoding is checked even when headers already declare a device ID.
func SourceDeviceID(headers http.Header, u *url.URL) (string, error) {
	params, err := orderedQueryParams(u)
	if err != nil {
		return "", err
	}
	return sourceDeviceID(headers, params), nil
}

func sourceDeviceID(headers http.Header, params []queryParam) string {
	if id := strings.TrimSpace(authFieldFromHeaders(headers, authDeviceIDFromValue)); id != "" {
		return id
	}
	for _, key := range []string{"xembydeviceid", "xmediabrowserdeviceid"} {
		if id := strings.TrimSpace(firstHeaderValueByNormalizedKey(headers, key)); id != "" {
			return id
		}
	}
	for _, param := range params {
		if !isAuthorizationKey(param.normalizedKey) {
			continue
		}
		if id := strings.TrimSpace(authDeviceIDFromValue(param.value)); id != "" {
			return id
		}
	}
	for _, param := range params {
		switch param.normalizedKey {
		case "xembydeviceid", "xmediabrowserdeviceid":
			if id := strings.TrimSpace(param.value); id != "" {
				return id
			}
		}
	}
	return ""
}

// WebSocketSourceDeviceID also accepts the bare deviceId parameter, which
// WebSocket clients use to bind their session.
func WebSocketSourceDeviceID(headers http.Header, u *url.URL) (string, error) {
	params, err := orderedQueryParams(u)
	if err != nil {
		return "", err
	}
	if id := sourceDeviceID(headers, params); id != "" {
		return id, nil
	}
	_, id := firstQueryParam(params, "deviceid")
	return strings.TrimSpace(id), nil
}

func authDeviceIDFromValue(auth string) string {
	return authFieldValue(embyAuthorizationDeviceIDRE, auth)
}

type queryParam struct {
	key           string
	normalizedKey string
	value         string
}

// orderedQueryParams decodes the raw query in its original order, which
// url.Values cannot preserve across different keys.
func orderedQueryParams(u *url.URL) ([]queryParam, error) {
	if u == nil {
		return nil, nil
	}
	var params []queryParam
	for rawQuery := u.RawQuery; rawQuery != ""; {
		var part string
		part, rawQuery, _ = strings.Cut(rawQuery, "&")
		if part == "" {
			continue
		}
		// Match url.ParseQuery: raw semicolons invalidate an entire pair. Do not
		// derive identity from a pair that downstream URL.Query would discard.
		if strings.Contains(part, ";") {
			return nil, fmt.Errorf("%w: unescaped semicolon", ErrInvalidQueryEncoding)
		}
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidQueryEncoding, err)
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidQueryEncoding, err)
		}
		params = append(params, queryParam{key: key, normalizedKey: normalizeHeaderKey(key), value: value})
	}
	return params, nil
}

// firstQueryParam returns the first query parameter in original order whose
// normalized key matches and whose value is not blank.
func firstQueryParam(params []queryParam, normalizedKey string) (string, string) {
	for _, param := range params {
		if param.normalizedKey == normalizedKey && strings.TrimSpace(param.value) != "" {
			return param.key, param.value
		}
	}
	return "", ""
}
