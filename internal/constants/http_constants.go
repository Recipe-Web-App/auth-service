// Package constants contains shared HTTP header names and
// common content type strings used across the service.
package constants

// Header names commonly used across the application.
const (
	// HeaderAccept is the HTTP "Accept" header name.
	HeaderAccept = "Accept"

	// HeaderAuthorization is the HTTP "Authorization" header name.
	HeaderAuthorization = "Authorization"

	// HeaderContentType is the HTTP "Content-Type" header name.
	HeaderContentType = "Content-Type"

	// HeaderReferer is the HTTP "Referer" header name.
	HeaderReferer = "Referer"

	// HeaderUserAgent is the HTTP "User-Agent" header name.
	HeaderUserAgent = "User-Agent"

	// HeaderXRequestID is the custom request ID header name.
	HeaderXRequestID = "X-Request-ID"
)

// Common media / content types used in requests and responses.
const (
	// ContentTypeJSON represents "application/json".
	ContentTypeJSON = "application/json"

	// ContentTypeJWT represents "application/jwt".
	ContentTypeJWT = "application/jwt"

	// ContentTypeFormURLEncoded represents
	// "application/x-www-form-urlencoded".
	ContentTypeFormURLEncoded = "application/x-www-form-urlencoded"

	// ContentTypeOctetStream represents "application/octet-stream".
	ContentTypeOctetStream = "application/octet-stream"

	// ContentTypeHTMLUTF8 represents "text/html; charset=utf-8".
	ContentTypeHTMLUTF8 = "text/html; charset=utf-8"

	// ContentTypePlainUTF8 represents "text/plain; charset=utf-8".
	ContentTypePlainUTF8 = "text/plain; charset=utf-8"
)
