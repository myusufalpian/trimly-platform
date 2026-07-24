package httputil

import (
	"encoding/json"
	"net/http"
)

type ResponseEnvelope struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *ErrorData  `json:"error,omitempty"`
}

type ErrorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ResponseEnvelope{
		Success: status >= 200 && status < 300,
		Data:    data,
	})
}

func RespondError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ResponseEnvelope{
		Success: false,
		Error: &ErrorData{
			Code:    code,
			Message: message,
		},
	})
}
