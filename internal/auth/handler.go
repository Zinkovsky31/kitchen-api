package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"kitchen-api/internal/user"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
	}
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type userResponse struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	CreatedAt string `json:"createdAt"`
}

type authResponse struct {
	AccessToken      string       `json:"accessToken"`
	RefreshToken     string       `json:"refreshToken"`
	AccessExpiresIn  int64        `json:"accessExpiresIn"`
	RefreshExpiresIn int64        `json:"refreshExpiresIn"`
	User             userResponse `json:"user"`
}

type tokenResponse struct {
	AccessToken      string `json:"accessToken"`
	RefreshToken     string `json:"refreshToken"`
	AccessExpiresIn  int64  `json:"accessExpiresIn"`
	RefreshExpiresIn int64  `json:"refreshExpiresIn"`
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (h *Handler) Register(
	w http.ResponseWriter,
	r *http.Request,
) {
	var request registerRequest

	if err := decodeJSON(r, &request); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"INVALID_REQUEST",
			"Invalid request body",
		)
		return
	}

	result, err := h.service.Register(
		r.Context(),
		request.Email,
		request.Password,
	)

	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		authResponse{
			AccessToken:      result.Tokens.AccessToken,
			RefreshToken:     result.Tokens.RefreshToken,
			AccessExpiresIn:  result.Tokens.AccessExpiresIn,
			RefreshExpiresIn: result.Tokens.RefreshExpiresIn,
			User:             makeUserResponse(result.User),
		},
	)
}

func (h *Handler) Login(
	w http.ResponseWriter,
	r *http.Request,
) {
	var request loginRequest

	if err := decodeJSON(r, &request); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"INVALID_REQUEST",
			"Invalid request body",
		)
		return
	}

	result, err := h.service.Login(
		r.Context(),
		request.Email,
		request.Password,
	)

	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		authResponse{
			AccessToken:      result.Tokens.AccessToken,
			RefreshToken:     result.Tokens.RefreshToken,
			AccessExpiresIn:  result.Tokens.AccessExpiresIn,
			RefreshExpiresIn: result.Tokens.RefreshExpiresIn,
			User:             makeUserResponse(result.User),
		},
	)
}

func (h *Handler) Refresh(
	w http.ResponseWriter,
	r *http.Request,
) {
	var request refreshRequest

	if err := decodeJSON(r, &request); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			"INVALID_REQUEST",
			"Invalid request body",
		)
		return
	}

	tokens, err := h.service.Refresh(
		r.Context(),
		request.RefreshToken,
	)

	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		tokenResponse{
			AccessToken:      tokens.AccessToken,
			RefreshToken:     tokens.RefreshToken,
			AccessExpiresIn:  tokens.AccessExpiresIn,
			RefreshExpiresIn: tokens.RefreshExpiresIn,
		},
	)
}

func (h *Handler) Logout(
	w http.ResponseWriter,
	r *http.Request,
) {
	accessToken := extractBearerToken(r)

	if err := h.service.Logout(
		r.Context(),
		accessToken,
	); err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"INTERNAL_ERROR",
			"Internal server error",
		)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Me(
	w http.ResponseWriter,
	r *http.Request,
) {
	accessToken := extractBearerToken(r)

	currentUser, err := h.service.Authenticate(
		r.Context(),
		accessToken,
	)

	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		makeUserResponse(currentUser),
	)
}

func (h *Handler) handleServiceError(
	w http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		writeError(
			w,
			http.StatusUnauthorized,
			"INVALID_CREDENTIALS",
			"Invalid email or password",
		)

	case errors.Is(err, ErrInvalidToken):
		writeError(
			w,
			http.StatusUnauthorized,
			"INVALID_TOKEN",
			"Invalid authentication token",
		)

	case errors.Is(err, ErrExpiredToken):
		writeError(
			w,
			http.StatusUnauthorized,
			"TOKEN_EXPIRED",
			"Authentication token has expired",
		)

	case errors.Is(err, ErrInvalidInput):
		writeError(
			w,
			http.StatusBadRequest,
			"VALIDATION_ERROR",
			err.Error(),
		)

	case errors.Is(err, user.ErrEmailExists):
		writeError(
			w,
			http.StatusConflict,
			"EMAIL_ALREADY_EXISTS",
			"Email is already registered",
		)

	default:
		writeError(
			w,
			http.StatusInternalServerError,
			"INTERNAL_ERROR",
			"Internal server error",
		)
	}
}

func makeUserResponse(
	currentUser *user.User,
) userResponse {
	return userResponse{
		ID:        currentUser.ID,
		Email:     currentUser.Email,
		CreatedAt: currentUser.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func decodeJSON(
	r *http.Request,
	target interface{},
) error {
	defer r.Body.Close()

	return json.NewDecoder(r.Body).Decode(target)
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(data)
}

func writeError(
	w http.ResponseWriter,
	status int,
	code string,
	message string,
) {
	writeJSON(
		w,
		status,
		errorResponse{
			Code:    code,
			Message: message,
		},
	)
}

func extractBearerToken(
	r *http.Request,
) string {
	header := r.Header.Get("Authorization")

	const prefix = "Bearer "

	if !strings.HasPrefix(header, prefix) {
		return ""
	}

	return strings.TrimSpace(
		strings.TrimPrefix(header, prefix),
	)
}
