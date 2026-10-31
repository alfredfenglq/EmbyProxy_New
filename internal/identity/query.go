package identity

import (
	"net/http"
	"net/url"
	"strings"
)

// ApplyToURL rewrites the identity fields of an API request URL with snap.
func ApplyToURL(u *url.URL, headers http.Header, snap Snapshot) {
	if u == nil {
		return
	}
	model := GetProfile(snap.Profile).requests
	switch model.apiQuery {
	case queryPromoteAuthToHeaders:
		applyQueryAuthToHeaders(u, headers, model.promotedAuthHeaders, false)
		setTokenHeaderIfMissing(headers, authTokenFromHeaders(headers))
		return
	case queryDuplicateIdentity:
		applyQueryIdentityToURL(u, headers, snap, model)
		return
	}
	setTokenHeaderIfMissing(headers, authTokenFromURL(u))
	applyProfileIdentityToURL(u, snap)
}

// ApplyToResourceURL rewrites the identity fields of a resource request URL
// with snap.
func ApplyToResourceURL(u *url.URL, headers http.Header, snap Snapshot) {
	if u == nil {
		return
	}
	model := GetProfile(snap.Profile).requests
	switch model.resourceQuery {
	case queryPromoteAuthToHeaders:
		applyQueryAuthToHeaders(u, headers, model.promotedAuthHeaders, true)
		setTokenHeaderIfMissing(headers, authTokenFromHeaders(headers))
		return
	case queryStripResourceIdentity:
		applyResourceQueryIdentityToHeaders(u, headers, snap, model)
		return
	}
	setTokenHeaderIfMissing(headers, authTokenFromURL(u))
	applyProfileIdentityToURL(u, snap)
}

// ApplyToDirectURL moves the tokens of a direct request URL to headers and
// rewrites its identity headers with snap.
func ApplyToDirectURL(u *url.URL, headers http.Header, snap Snapshot) {
	setTokenHeaderIfMissing(headers, firstSanitizedToken(
		firstQueryValueByNormalizedKey(u, "xembytoken"),
		firstQueryValueByNormalizedKey(u, "xmediabrowsertoken"),
		authTokenFromURL(u),
	))
	ApplyToHeaders(headers, snap)
}

func setTokenHeaderIfMissing(headers http.Header, token string) {
	if headers == nil || headersHaveNonEmptyValue(headers, "X-Emby-Token") || strings.TrimSpace(token) == "" {
		return
	}
	headers.Set("X-Emby-Token", sanitizeHeaderValue(token))
}

func applyQueryIdentityToURL(u *url.URL, headers http.Header, snap Snapshot, model requestModel) {
	if snap.DeviceID == "" || !queryOrHeaderAuthorizationPresent(u, headers) {
		// Without authorization, or without a source device to derive an
		// identity from, there is no identity to duplicate, but source identity
		// fields must not leak next to the impersonated UA. Token parameters
		// stay and a query authorization token moves to the header, so the
		// request remains authenticated.
		queryAuthToken := authTokenFromURL(u)
		q := u.Query()
		if removeResourceQueryIdentity(q) {
			u.RawQuery = q.Encode()
		}
		if !hasNonEmptyQueryKey(q, "apikey", "xembytoken", "xmediabrowsertoken") {
			setTokenHeaderIfMissing(headers, queryAuthToken)
		}
		return
	}
	q := u.Query()
	hasQueryAuthorization := queryAuthorizationPresent(u)
	token := apiTokenForURL(u, headers)
	removeQueryIdentity(q)
	q.Set("X-Emby-Authorization", model.authorization.format(snap))
	q.Set("X-Emby-Client", snap.ClientName)
	q.Set("X-Emby-Device-Name", snap.DeviceName)
	q.Set("X-Emby-Device-Id", snap.DeviceID)
	q.Set("X-Emby-Client-Version", snap.ClientVersion)
	q.Set("X-Emby-Language", queryLanguageForURL(u, model))
	if token != "" {
		q.Set("X-Emby-Token", token)
		if headers != nil {
			headers.Set("X-Emby-Token", sanitizeHeaderValue(token))
		}
	}
	if hasQueryAuthorization && headers != nil && firstEmbyAuthorizationHeader(headers) == "" {
		headers.Set("X-Emby-Authorization", model.authorization.format(snap))
	}
	u.RawQuery = q.Encode()
}

func queryLanguageForURL(u *url.URL, model requestModel) string {
	if isUsersRootPath(u) {
		return model.userRootLanguage
	}
	return model.defaultLanguage
}

func isUsersRootPath(u *url.URL) bool {
	if u == nil {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, part := range parts {
		if !strings.EqualFold(part, "users") {
			continue
		}
		if i+2 != len(parts) {
			return false
		}
		segment := strings.TrimSpace(parts[i+1])
		return segment != "" && !isUsersCollectionAction(segment)
	}
	return false
}

func isUsersCollectionAction(segment string) bool {
	switch strings.ToLower(strings.TrimSpace(segment)) {
	case "authenticate", "authenticatebyname", "public", "new", "forgotpassword", "query":
		return true
	default:
		return false
	}
}

func applyResourceQueryIdentityToHeaders(u *url.URL, headers http.Header, snap Snapshot, model requestModel) {
	hasQueryAuthorization := queryAuthorizationPresent(u)
	// Query authorization is removed below; keep its token so the request stays authenticated.
	queryAuthToken := authTokenFromURL(u)
	q := u.Query()
	if removeResourceQueryIdentity(q) {
		u.RawQuery = q.Encode()
	}
	if hasQueryAuthorization && snap.DeviceID != "" && headers != nil && firstEmbyAuthorizationHeader(headers) == "" {
		headers.Set("X-Emby-Authorization", model.authorization.format(snap))
	}
	ApplyToHeaders(headers, snap)
	// Do not promote query authorization above an explicit query token.
	if !hasNonEmptyQueryKey(q, "apikey", "xembytoken", "xmediabrowsertoken") {
		setTokenHeaderIfMissing(headers, queryAuthToken)
	}
}

func removeQueryIdentity(q url.Values) bool {
	changed := false
	for key, values := range q {
		if isQueryIdentityParam(normalizeHeaderKey(key), values) {
			q.Del(key)
			changed = true
		}
	}
	return changed
}

func removeResourceQueryIdentity(q url.Values) bool {
	changed := false
	for key, values := range q {
		normalizedKey := normalizeHeaderKey(key)
		if normalizedKey == "xembytoken" || normalizedKey == "xmediabrowsertoken" {
			continue
		}
		if isQueryIdentityParam(normalizedKey, values) {
			q.Del(key)
			changed = true
		}
	}
	return changed
}

func queryOrHeaderAuthorizationPresent(u *url.URL, headers http.Header) bool {
	return firstEmbyAuthorizationHeader(headers) != "" || queryAuthorizationPresent(u)
}

func queryAuthorizationPresent(u *url.URL) bool {
	if u == nil {
		return false
	}
	for key, values := range u.Query() {
		normalizedKey := normalizeHeaderKey(key)
		switch normalizedKey {
		case "authorization", "xauthorization", "xembyauthorization", "xmediabrowserauthorization":
			for _, value := range values {
				if isEmbyAuthorization(value) {
					return true
				}
			}
		}
	}
	return false
}

func apiTokenForURL(u *url.URL, headers http.Header) string {
	return firstSanitizedToken(
		firstHeaderValue(headers, "X-Emby-Token"),
		firstHeaderValue(headers, "X-MediaBrowser-Token"),
		firstHeaderValueByNormalizedKey(headers, "xembytoken"),
		firstHeaderValueByNormalizedKey(headers, "xmediabrowsertoken"),
		firstQueryValueByNormalizedKey(u, "xembytoken"),
		firstQueryValueByNormalizedKey(u, "xmediabrowsertoken"),
		authTokenFromURL(u),
		authTokenFromHeaders(headers),
	)
}

func firstSanitizedToken(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return sanitizeHeaderValue(value)
		}
	}
	return ""
}

func firstQueryValueByNormalizedKey(u *url.URL, normalizedKey string) string {
	if u == nil {
		return ""
	}
	for key, values := range u.Query() {
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

func authTokenFromURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	for key, values := range u.Query() {
		if !isAuthorizationKey(normalizeHeaderKey(key)) {
			continue
		}
		for _, value := range values {
			if token := authTokenFromValue(value); token != "" {
				return token
			}
		}
	}
	return ""
}

func isAuthorizationKey(normalizedKey string) bool {
	switch normalizedKey {
	case "authorization", "xauthorization", "xembyauthorization", "xmediabrowserauthorization":
		return true
	default:
		return false
	}
}

func isQueryIdentityParam(normalizedKey string, values []string) bool {
	if strings.HasPrefix(normalizedKey, "xemby") || strings.HasPrefix(normalizedKey, "xmediabrowser") {
		return true
	}
	switch normalizedKey {
	case "deviceid":
		return true
	case "authorization", "xauthorization":
		for _, value := range values {
			if isEmbyAuthorization(value) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func applyProfileIdentityToURL(u *url.URL, snap Snapshot) {
	q := u.Query()
	if snap.DeviceID == "" {
		// No device identity to rewrite with: drop the source identity and
		// keep token parameters.
		if removeResourceQueryIdentity(q) {
			u.RawQuery = q.Encode()
		}
		return
	}
	changed := false
	for key, values := range q {
		if len(values) == 0 {
			continue
		}
		switch normalizeHeaderKey(key) {
		case "xembyclient", "xmediabrowserclient":
			q.Set(key, snap.ClientName)
			changed = true
		case "xembyclientversion", "xmediabrowserclientversion":
			q.Set(key, snap.ClientVersion)
			changed = true
		case "xembydevicename", "xmediabrowserdevicename", "devicename":
			q.Set(key, snap.DeviceName)
			changed = true
		case "xembydeviceid", "xmediabrowserdeviceid", "deviceid":
			q.Set(key, snap.DeviceID)
			changed = true
		case "xembyauthorization", "xmediabrowserauthorization", "xauthorization", "authorization":
			q.Set(key, RewriteMediaBrowserAuthorization(values[0], snap))
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
}

func applyQueryAuthToHeaders(u *url.URL, headers http.Header, authHeaders map[string]string, preserveBareIdentity bool) {
	q := u.Query()
	changed := false

	for rawQuery := u.RawQuery; rawQuery != ""; {
		var part string
		part, rawQuery, _ = strings.Cut(rawQuery, "&")
		if part == "" {
			continue
		}
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		normalizedKey := normalizeHeaderKey(key)
		if canonical, ok := authHeaders[normalizedKey]; ok {
			if headers != nil && !headersHaveNonEmptyValue(headers, canonical) {
				value, err := url.QueryUnescape(rawValue)
				if err != nil {
					value = rawValue
				}
				headers.Set(canonical, sanitizeHeaderValue(value))
			}
			q.Del(key)
			changed = true
			continue
		}
		if isPromotedQueryIdentityKey(normalizedKey) {
			if preserveBareIdentity && normalizedKey == "devicename" {
				continue
			}
			q.Del(key)
			changed = true
		}
	}

	if changed {
		u.RawQuery = q.Encode()
	}
}

func isPromotedQueryIdentityKey(normalizedKey string) bool {
	if strings.HasPrefix(normalizedKey, "xemby") || strings.HasPrefix(normalizedKey, "xmediabrowser") {
		return true
	}
	switch normalizedKey {
	case "deviceid", "devicename":
		return true
	default:
		return false
	}
}
