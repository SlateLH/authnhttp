package authnhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/SlateLH/authn"
)

type Router interface {
	Handle(handler Handler) error
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

type router struct {
	mux     *http.ServeMux
	svc     authn.Service
	methods map[authn.Method]Handler
}

func (r *router) Handle(handler Handler) error {
	if handler == nil {
		return errors.New("invalid handler")
	}

	if err := r.svc.Register(handler.Authenticator()); err != nil {
		return fmt.Errorf("%w: %v", errors.New("failed to register method"), err)
	}

	existing, ok := r.methods[handler.Method()]
	if existing != nil || ok {
		return fmt.Errorf("method \"%s\" already registered", handler.Method())
	}

	r.methods[handler.Method()] = handler
	return nil
}

func (r *router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func (r router) handleInitiate(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(req.Body)
	if err != nil {
		res := ErrorResponse{
			Error:   "read error",
			Message: "body could not be read",
		}

		writeError(w, http.StatusBadRequest, res)
		return
	}

	var initiateReq InitiateRequest
	if err := json.Unmarshal(body, &initiateReq); err != nil {
		res := ErrorResponse{
			Error:   "parse error",
			Message: "invalid json body",
		}

		writeError(w, http.StatusBadRequest, res)
		return
	}

	if initiateReq.Method == "" {
		res := ErrorResponse{
			Error:   "validation error",
			Message: "field \"method\" is required",
		}

		writeError(w, http.StatusBadRequest, res)
		return
	}

	handler, ok := r.methods[initiateReq.Method]
	if !ok {
		res := ErrorResponse{
			Error:   "validation error",
			Message: "unregistered method",
		}

		writeError(w, http.StatusUnprocessableEntity, res)
		return
	}

	creds, err := handler.BuildCredentials(initiateReq)
	if err != nil {
		res := ErrorResponse{
			Error:   "parse error",
			Message: "invalid json payload",
		}

		writeError(w, http.StatusBadRequest, res)
		return
	}

	result, err := r.svc.Initiate(req.Context(), creds)
	if err != nil {
		res := ErrorResponse{
			Error:   "initiate error",
			Message: err.Error(),
		}

		writeError(w, http.StatusBadRequest, res)
		return
	}

	if result.Status == authn.StatusFailed {
		res := ErrorResponse{
			Error:   "authentication error",
			Message: "unauthorized",
		}

		writeError(w, http.StatusUnauthorized, res)
		return
	}

	writeResult(w, handler, result)
}

type routerOption func(*router)

func WithMux(mux *http.ServeMux) routerOption {
	return func(r *router) {
		r.mux = mux
	}
}

func WithSvc(svc authn.Service) routerOption {
	return func(r *router) {
		r.svc = svc
	}
}

func New(options ...routerOption) Router {
	methods := make(map[authn.Method]Handler)

	router := &router{
		methods: methods,
	}

	for _, option := range options {
		option(router)
	}

	if router.mux == nil {
		router.mux = http.NewServeMux()
	}

	if router.svc == nil {
		router.svc = authn.New()
	}

	router.mux.HandleFunc("POST /initiate", router.handleInitiate)

	return router
}
