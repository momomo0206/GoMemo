package auth

import (
	"net/http"
	"strings"
)

// ExtractBearerToken extracts the JWT token from an Authorization header value.
// Expected format: "Bearer {token}"
// Returns empty string if no valid bearer token is found.
func ExtractBearerToken(authHedader string) string {
	if authHedader == "" {
		return ""
	}
	parts := strings.Fields(authHedader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// ExtractRefreshTokenFromCookie extracts the refresh token from a cookie header.
func ExtractRefreshTokenFromCookie(cookieHeader string) string {
	if cookieHeader == "" {
		return ""
	}
	req := &http.Request{Header: http.Header{"Cookie": []string{cookieHeader}}}
	cookie, err := req.Cookie(RefreshTokenCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}
