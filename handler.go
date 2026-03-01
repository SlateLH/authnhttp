package authnhttp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/SlateLH/authn"
)

type Handler interface {
	Method() authn.Method
	Authenticator() authn.Authenticator
	BuildCredentials(request InitiateRequest) (authn.Credentials, error)
	BuildChallenge(challenge authn.Challenge) (Challenge, error)
	BuildSession(session authn.Session) (Session, error)
	HandleRespond(w http.ResponseWriter, r *http.Request)
}

func writeResult(w http.ResponseWriter, handler Handler, result authn.Result) {
	challenge, err := handler.BuildChallenge(result.Challenge)
	if err != nil {
		res := ErrorResponse{
			Error:   "encoding error",
			Message: fmt.Sprintf("error building challenge: %v", err.Error()),
		}

		writeError(w, http.StatusInternalServerError, res)
		return
	}

	session, err := handler.BuildSession(result.Session)
	if err != nil {
		res := ErrorResponse{
			Error:   "encoding error",
			Message: fmt.Sprintf("error building session: %v", err.Error()),
		}

		writeError(w, http.StatusInternalServerError, res)
		return
	}

	identity := IdentityDTO{
		ID: result.Identity.ID,
	}

	response := ResultResponse{
		Status:    result.Status,
		Identity:  identity,
		Challenge: challenge,
		Session:   session,
	}

	marshalled, err := json.Marshal(response)
	if err != nil {
		res := ErrorResponse{
			Error:   "encoding error",
			Message: err.Error(),
		}

		writeError(w, http.StatusInternalServerError, res)
		return
	}

	w.Write(marshalled)
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
