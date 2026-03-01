package authnhttp

import (
	"encoding/json"

	"github.com/SlateLH/authn"
)

type IdentifierDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type InitiateRequest struct {
	Method     authn.Method    `json:"method"`
	Identifier IdentifierDTO   `json:"identifier"`
	Payload    json.RawMessage `json:"payload"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
