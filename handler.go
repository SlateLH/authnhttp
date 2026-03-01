package authnhttp

import (
	"encoding/json"
	"net/http"

	"github.com/SlateLH/authn"
)

type Handler interface {
	Method() authn.Method
	Authenticator() authn.Authenticator
	BuildCredentials(request InitiateRequest) (authn.Credentials, error)
	HandleRespond(w http.ResponseWriter, r *http.Request)
}

func writeError(w http.ResponseWriter, statusCode int, res ErrorResponse) {
	marshalled, err := json.Marshal(res)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{\"error\":\"encoding error\",\"message\":\"error marshalling json data\"}"))
	} else {
		w.WriteHeader(statusCode)
		w.Write(marshalled)
	}
}
