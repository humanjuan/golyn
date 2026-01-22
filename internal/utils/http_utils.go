package utils

import "net/http"

var httpCodeMessages = map[int]string{
	http.StatusContinue:            "[Continue] Server received the request and the client may continue sending the body.",
	http.StatusSwitchingProtocols:  "[Switching Protocols] The server agreed to switch protocols.",
	http.StatusOK:                  "[OK] The request completed successfully.",
	http.StatusCreated:             "[Created] A new resource was created.",
	http.StatusAccepted:            "[Accepted] The request was accepted for processing, but is not complete.",
	http.StatusNoContent:           "[No Content] The request completed successfully and there is no response body.",
	http.StatusMultipleChoices:     "[Multiple Choices] Multiple options are available for the requested resource.",
	http.StatusMovedPermanently:    "[Moved Permanently] The resource has moved permanently.",
	http.StatusFound:               "[Found] The resource is temporarily available at a different location.",
	http.StatusNotModified:         "[Not Modified] The resource has not changed; a cached version may be used.",
	http.StatusBadRequest:          "[Bad Request] The request is invalid or cannot be understood.",
	http.StatusUnauthorized:        "[Unauthorized] Authentication is required.",
	http.StatusForbidden:           "[Forbidden] The server understood the request but refuses to authorize it.",
	http.StatusNotFound:            "[Not Found] The requested resource was not found.",
	http.StatusMethodNotAllowed:    "[Method Not Allowed] The HTTP method is not allowed for this route.",
	http.StatusMisdirectedRequest:  "[Misdirected Request] The request was sent to a server that cannot produce a response.",
	http.StatusInternalServerError: "[Internal Server Error] The server encountered an unexpected condition.",
	http.StatusNotImplemented:      "[Not Implemented] The server does not support the requested functionality.",
	http.StatusBadGateway:          "[Bad Gateway] The gateway/proxy received an invalid response from the upstream server.",
	http.StatusServiceUnavailable:  "[Service Unavailable] The server is not ready to handle the request.",
}

// APIResponse is the standard structure for all API responses
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func GetCodeMessage(code int) string {
	message, exists := httpCodeMessages[code]
	if exists {
		return message
	}
	return "Unknown HTTP Code"
}

func StringToSameSite(s string) http.SameSite {
	switch s {
	case "Lax":
		return http.SameSiteLaxMode
	case "Strict":
		return http.SameSiteStrictMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
