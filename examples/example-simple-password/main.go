package main

import (
	"bytes"
	"context"
	"log"
	"net/http"

	"github.com/SlateLH/authn"
	authnPassword "github.com/SlateLH/authn/authenticators/password"
	"github.com/SlateLH/authnhttp"
	authnhttpPassword "github.com/SlateLH/authnhttp/handlers/password"
)

var identityIDs = map[string]string{
	"user1": "id-1",
	"user2": "id-2",
}

var passwords = map[string][]byte{
	"id-1": []byte("password1"),
	"id-2": []byte("password2"),
}

type identityResolver struct{}

func (r identityResolver) Resolve(ctx context.Context, identifier authn.Identifier) (identityID string, err error) {
	identityID, ok := identityIDs[identifier.Value]
	if !ok {
		return "", authn.ErrIdentityNotFound
	}

	return identityID, nil
}

type passwordStore struct{}

func (s passwordStore) FindPassword(ctx context.Context, identityID string) (pass []byte, err error) {
	pass, ok := passwords[identityID]
	if !ok {
		return []byte{}, authnPassword.ErrPasswordNotFound
	}

	return pass, nil
}

type passwordVerifier struct{}

func (v passwordVerifier) Verify(ctx context.Context, pass []byte, plain string) error {
	if !bytes.Equal(pass, []byte(plain)) {
		return authnPassword.ErrWrongPassword
	}

	return nil
}

func main() {
	logger := log.Default()

	passwordDeps := authnPassword.AuthenticatorDeps{
		IdentityResolver: identityResolver{},
		Store:            passwordStore{},
		Verifier:         passwordVerifier{},
	}

	passwordHandler, err := authnhttpPassword.NewHandler(passwordDeps)
	if err != nil {
		logger.Fatalln("error creating password handler:", err)
	}

	mux := http.NewServeMux()

	authRouter := authnhttp.New()
	authRouter.Handle(passwordHandler)

	mux.Handle("/authn/", http.StripPrefix("/authn", authRouter))

	logger.Println("starting server on :8080")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		logger.Fatalln("server error:", err)
	}
}
