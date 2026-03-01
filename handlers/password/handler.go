package password

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/SlateLH/authn"
	"github.com/SlateLH/authn/authenticators/password"
	"github.com/SlateLH/authnhttp"
)

type handler struct {
	auth authn.Authenticator
}

func (h handler) Method() authn.Method {
	return password.Method
}

func (h handler) Authenticator() authn.Authenticator {
	return h.auth
}

func (h handler) BuildCredentials(request authnhttp.InitiateRequest) (authn.Credentials, error) {
	identifier := authn.Identifier{
		Type:  authn.IdentifierType(request.Identifier.Type),
		Value: request.Identifier.Value,
	}

	var payload PayloadDTO
	if err := json.Unmarshal(request.Payload, &payload); err != nil {
		return nil, err
	}

	return password.NewCredentials(identifier, payload.Password), nil
}

func (h handler) BuildChallenge(challenge authn.Challenge) (authnhttp.Challenge, error) {
	return nil, nil
}

func (h handler) BuildSession(session authn.Session) (authnhttp.Session, error) {
	return nil, nil
}

func (h handler) HandleRespond(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(400)
}

func NewHandler(deps password.AuthenticatorDeps) (authnhttp.Handler, error) {
	auth, err := password.NewAuthenticator(deps)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.New("failed to create password authenticator"), err)
	}

	handler := &handler{
		auth: auth,
	}

	return handler, nil
}
