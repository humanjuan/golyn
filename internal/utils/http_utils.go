package utils

const (
	Continue            = 100
	SwitchingProtocols  = 101
	OK                  = 200
	Created             = 201
	Accepted            = 202
	NoContent           = 204
	MultipleChoices     = 300
	MovedPermanently    = 301
	Found               = 302
	NotModified         = 304
	BadRequest          = 400
	Unauthorized        = 401
	Forbidden           = 403
	NotFound            = 404
	MethodNotAllowed    = 405
	MisdirectedRequest  = 421
	InternalServerError = 500
	NotImplemented      = 501
	BadGateway          = 502
	ServiceUnavailable  = 503
)

var httpCodeMessages = map[int]string{
	Continue:            "[Continue] Server received the requested and the client can continue sending the rest of the request.",
	SwitchingProtocols:  "[Switching Protocol] The server accept to change the requested protocol.",
	OK:                  "[OK] The request has been completed successfully.",
	Created:             "[Created] The request resulted in the creation of a new resource.",
	Accepted:            "[Accepted] The request has been accepted to processing, but hasn't been completed yet.",
	NoContent:           "[No Content] The request has been completed successfully, but there isn't body respond (e.g.: DELETE request)",
	MultipleChoices:     "[Multiple Choices] The request indicates multiple options available.",
	MovedPermanently:    "[Moved Permanently] The resource requested has been moved to other location permanently.",
	Found:               "[Found (or 303 See Other)] The resource requested is found temporarily in a different location.",
	NotModified:         "[Not Modified] Indicates that the resource hasn't been modified and can use the cache version.",
	BadRequest:          "[Bad Request] The client request is incorrect or it can't be understood.",
	Unauthorized:        "[Unauthorized] The client doesn't have the necessary authorization to access to the resource.",
	Forbidden:           "[Forbidden] The server understood the request but refuses to authorize it.",
	NotFound:            "[Not Found] The requested resource is not found in the server.",
	MethodNotAllowed:    "[Method Not Allowed] The requested HTTP method it doesn't allow for this route.",
	MisdirectedRequest:  "[Misdirected Request] The request was directed at a server that is not able to produce a response.",
	InternalServerError: "[Internal Server Error] Indicates an internal error in the server.",
	NotImplemented:      "[Not Implemented] The server can't achieve the request because it doesn't recognize the action.",
	BadGateway:          "[Bad Gateway] The server, as long as acted like a gateway or proxy, received an invalid respond from the upstream server.",
	ServiceUnavailable:  "[Service Unavailable] The server is not ready to handle the request. May be due to overload or maintenance.",
}

func GetCodeMessage(code int) string {
	message, exists := httpCodeMessages[code]
	if exists {
		return message
	}
	return "Unknown HTTP Code"
}
