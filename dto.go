package authnhttp

import (
	"encoding/json"

	"github.com/SlateLH/authn"
)

type IdentifierDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type IdentityDTO struct {
	ID string `json:"id"`
}

type Challenge interface {
	Marshal(v any) error
}

type Session interface {
	Marshal(v any) error
}

type InitiateRequest struct {
	Method     authn.Method    `json:"method"`
	Identifier IdentifierDTO   `json:"identifier"`
	Payload    json.RawMessage `json:"payload"`
}

type ResultResponse struct {
	Status    authn.Status `json:"status"`
	Identity  IdentityDTO  `json:"identity"`
	Challenge Challenge    `json:"challenge"`
	Session   Session      `json:"session"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
