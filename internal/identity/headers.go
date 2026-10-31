package identity

import (
	"net/http"
	"regexp"
	"strings"
)

var (
	embyAuthorizationRE      = regexp.MustCompile(`(?i)^(?:MediaBrowser|Emby)(?:\s|$)`)
	embyAuthorizationTokenRE = regexp.MustCompile(`(?i)^(?:MediaBrowser|Emby)(?:\s|$).*?\bToken\s*=\s*("[^"]*"|[^,\s]+)`)
	authorizationHeaderKeys  = []string{"X-Emby-Authorization", "X-MediaBrowser-Authorization", "Authorization", "X-Authorization"}
)

// ApplyToHeaders replaces the source identity headers with snap. Source
// authorization becomes the impersonated authorization only when snap carries
// a device identity; otherwise only the token is kept.
func ApplyToHeaders(headers http.Header, snap Snapshot) {
	if headers == nil {
		return
	}
	token := identityTokenFromHeaders(headers)
	auth := firstEmbyAuthorizationHeader(headers)
	stripImpersonationHeaders(headers)
	if auth != "" && snap.DeviceID != "" {
		headers.Set("X-Emby-Authorization", GetProfile(snap.Profile).requests.authorization.format(snap))
	}
	if token != "" {
		headers.Set("X-Emby-Token", token)
	}
}

func stripImpersonationHeaders(headers http.Header) {
	for key := range cloneHeader(headers) {
		normalized := normalizeHeaderKey(key)
		switch {
		case normalized == "xembytoken":
			if !strings.EqualFold(key, "X-Emby-Token") {
				deleteHeaderKey(headers, key)
			}
			continue
		case normalized == "xembyauthorization":
			deleteHeaderKey(headers, key)
		case isStandaloneIdentityHeader(normalized):
			deleteHeaderKey(headers, key)
		case strings.HasPrefix(normalized, "xmediabrowser"):
			deleteHeaderKey(headers, key)
		case normalized == "xauthorization":
			deleteHeaderKey(headers, key)
		case normalized == "authorization" && isEmbyAuthorization(headers.Get(key)):
			deleteHeaderKey(headers, key)
		}
	}
}

func isStandaloneIdentityHeader(normalizedKey string) bool {
	switch normalizedKey {
	case "xembyclient", "xembyclientversion", "xembydevicename", "xembydeviceid", "xembylanguage", "xapplication":
		return true
	default:
		return false
	}
}

func deleteHeaderKey(headers http.Header, key string) {
	delete(headers, key)
	headers.Del(key)
}

// sanitizeHeaderValue strips control characters (CR/LF and other bytes below
// space, plus the lone DEL) that net/http rejects when sending a request.
// Values promoted from URL query parameters are untrusted input, so removing
// them here keeps the request sendable instead of letting the transport fail
// with "invalid header field value".
func sanitizeHeaderValue(value string) string {
	if !strings.ContainsAny(value, "\r\n") && !containsHeaderValueControlByte(value) {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r == '\r' || r == '\n' || r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// containsHeaderValueControlByte reports whether value contains an ASCII
// control byte (0x00-0x1F) or DEL (0x7F) outside of the allowed HT (0x09).
func containsHeaderValueControlByte(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func RewriteMediaBrowserAuthorization(value string, snap Snapshot) string {
	raw := strings.TrimSpace(value)
	if !isEmbyAuthorization(raw) {
		return value
	}
	style := GetProfile(snap.Profile).requests.authorization
	// Preserve the legacy ClientName fallback for standalone snapshots that
	// predate the Profile field; Manager snapshots always carry a profile.
	if snap.Profile == "" && strings.ToLower(strings.TrimSpace(snap.ClientName)) != DefaultProfile {
		style = hillsRequestModel.authorization
	}
	return style.format(snap)
}

func isEmbyAuthorization(value string) bool {
	return embyAuthorizationRE.MatchString(strings.TrimSpace(value))
}

func escapeMediaBrowserValue(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`)
}

func authTokenFromValue(auth string) string {
	return authFieldValue(embyAuthorizationTokenRE, auth)
}

func authFieldValue(re *regexp.Regexp, auth string) string {
	matches := re.FindStringSubmatch(strings.TrimSpace(auth))
	if len(matches) < 2 {
		return ""
	}
	return unquoteAuthFieldValue(matches[1])
}

func authTokenFromHeaders(headers http.Header) string {
	return authFieldFromHeaders(headers, authTokenFromValue)
}

// authFieldFromHeaders returns the first non-empty field extracted from the
// authorization headers, preferring canonical keys over aliases.
func authFieldFromHeaders(headers http.Header, field func(string) string) string {
	for _, key := range authorizationHeaderKeys {
		if value := field(firstHeaderValue(headers, key)); value != "" {
			return value
		}
	}
	for key, values := range headers {
		if !isAuthorizationKey(normalizeHeaderKey(key)) {
			continue
		}
		for _, value := range values {
			if extracted := field(value); extracted != "" {
				return extracted
			}
		}
	}
	return ""
}

func identityTokenFromHeaders(headers http.Header) string {
	return firstSanitizedToken(
		firstHeaderValue(headers, "X-Emby-Token"),
		firstHeaderValue(headers, "X-MediaBrowser-Token"),
		firstHeaderValueByNormalizedKey(headers, "xembytoken"),
		firstHeaderValueByNormalizedKey(headers, "xmediabrowsertoken"),
		authTokenFromHeaders(headers),
	)
}

func firstEmbyAuthorizationHeader(headers http.Header) string {
	for _, key := range authorizationHeaderKeys {
		value := firstHeaderValue(headers, key)
		if isEmbyAuthorization(value) {
			return value
		}
	}
	for key, values := range headers {
		if !isAuthorizationKey(normalizeHeaderKey(key)) {
			continue
		}
		for _, value := range values {
			if isEmbyAuthorization(value) {
				return value
			}
		}
	}
	return ""
}

func unquoteAuthFieldValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
		value = strings.ReplaceAll(value, `\"`, `"`)
		value = strings.ReplaceAll(value, `\\`, `\`)
	}
	return value
}

func firstHeaderValue(headers http.Header, canonical string) string {
	if headers == nil {
		return ""
	}
	for key, values := range headers {
		if !strings.EqualFold(key, canonical) {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

func firstHeaderValueByNormalizedKey(headers http.Header, normalizedKey string) string {
	if headers == nil {
		return ""
	}
	for key, values := range headers {
		if normalizeHeaderKey(key) != normalizedKey {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

func headersHaveNonEmptyValue(headers http.Header, canonical string) bool {
	return firstHeaderValue(headers, canonical) != ""
}

func normalizeHeaderKey(value string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(value))
}

func cloneHeader(in http.Header) http.Header {
	out := http.Header{}
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}
