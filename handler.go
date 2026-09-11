package authlier

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/sessiontoken"
)

const maximumRequestBody = 1 << 20

type httpHandler struct {
	auth           *Auth
	allowedOrigins []string
	cookie         http.Cookie
	mux            *http.ServeMux
}

type credentialsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userResponse struct {
	User emailpassword.User `json:"user"`
}

type sessionResponse struct {
	Session sessionDetails `json:"session"`
}

type sessionDetails struct {
	SubjectID string    `json:"subjectId"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type errorResponse struct {
	Error errorDetails `json:"error"`
}

type errorDetails struct {
	Code string `json:"code"`
}

func newHandler(auth *Auth, config Config, baseURL *url.URL, basePath string) (http.Handler, error) {
	origins := []string{baseURL.Scheme + "://" + baseURL.Host}
	for _, rawOrigin := range config.TrustedOrigins {
		origin, err := url.Parse(strings.TrimSpace(rawOrigin))
		if err != nil || (origin.Scheme != "https" && origin.Scheme != "http") || origin.Host == "" ||
			origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
			return nil, fmt.Errorf("%w: invalid trusted origin", ErrInvalidConfig)
		}
		origins = append(origins, origin.Scheme+"://"+origin.Host)
	}
	cookie := config.Session.Cookie
	if strings.TrimSpace(cookie.Name) == "" {
		cookie.Name = "authlier_session"
	}
	if cookie.Path == "" {
		cookie.Path = "/"
	}
	if cookie.SameSite == 0 {
		cookie.SameSite = http.SameSiteLaxMode
	}
	if cookie.SameSite == http.SameSiteNoneMode && baseURL.Scheme != "https" {
		return nil, fmt.Errorf("%w: SameSite=None requires HTTPS", ErrInvalidConfig)
	}
	auth.cookieName = cookie.Name
	handler := &httpHandler{
		auth:           auth,
		allowedOrigins: origins,
		cookie: http.Cookie{
			Name:     cookie.Name,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			HttpOnly: true,
			Secure:   baseURL.Scheme == "https",
			SameSite: cookie.SameSite,
		},
		mux: http.NewServeMux(),
	}
	handler.mux.HandleFunc("POST "+basePath+"/sign-up/email", handler.signUp)
	handler.mux.HandleFunc("POST "+basePath+"/sign-in/email", handler.signIn)
	handler.mux.HandleFunc("POST "+basePath+"/sign-out", handler.signOut)
	handler.mux.HandleFunc("GET "+basePath+"/session", handler.session)
	return handler, nil
}

func (handler *httpHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	origin := request.Header.Get("Origin")
	if origin != "" && handler.validOrigin(origin) {
		response.Header().Set("Access-Control-Allow-Origin", origin)
		response.Header().Set("Access-Control-Allow-Credentials", "true")
		response.Header().Add("Vary", "Origin")
	}
	if request.Method == http.MethodOptions {
		if !handler.validOrigin(origin) {
			writeError(response, http.StatusForbidden, "origin_not_allowed")
			return
		}
		response.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		response.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if request.Method != http.MethodGet && !handler.validOrigin(origin) {
		writeError(response, http.StatusForbidden, "origin_not_allowed")
		return
	}
	handler.mux.ServeHTTP(response, request)
}

func (handler *httpHandler) signUp(response http.ResponseWriter, request *http.Request) {
	input, ok := readCredentials(response, request)
	if !ok {
		return
	}
	user, err := handler.auth.password.Register(request.Context(), emailpassword.RegisterInput{
		Email: input.Email, Password: input.Password, SourceKey: sourceKey(request),
	})
	if err != nil {
		writeAuthenticationError(response, err)
		return
	}
	issued, err := handler.auth.sessions.Create(request.Context(), user.ID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "session_failed")
		return
	}
	handler.setSession(response, issued.Token, issued.Record.ExpiresAt)
	writeJSON(response, http.StatusCreated, userResponse{User: user})
}

func (handler *httpHandler) signIn(response http.ResponseWriter, request *http.Request) {
	input, ok := readCredentials(response, request)
	if !ok {
		return
	}
	login, err := handler.auth.password.Login(request.Context(), emailpassword.LoginInput{
		Email: input.Email, Password: input.Password, SourceKey: sourceKey(request),
	})
	if err != nil {
		writeAuthenticationError(response, err)
		return
	}
	issued, err := handler.auth.sessions.Create(request.Context(), login.User.ID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "session_failed")
		return
	}
	handler.setSession(response, issued.Token, issued.Record.ExpiresAt)
	writeJSON(response, http.StatusOK, userResponse{User: login.User})
}

func (handler *httpHandler) signOut(response http.ResponseWriter, request *http.Request) {
	cookie, err := request.Cookie(handler.cookie.Name)
	if err == nil {
		if err := handler.auth.sessions.Revoke(request.Context(), cookie.Value); err != nil &&
			!errors.Is(err, sessiontoken.ErrNotFound) && !errors.Is(err, sessiontoken.ErrInvalidToken) {
			writeError(response, http.StatusInternalServerError, "sign_out_failed")
			return
		}
	}
	expired := handler.cookie
	expired.Value = ""
	expired.MaxAge = -1
	http.SetCookie(response, &expired)
	response.WriteHeader(http.StatusNoContent)
}

func (handler *httpHandler) session(response http.ResponseWriter, request *http.Request) {
	record, err := handler.auth.ResolveSession(request)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "not_authenticated")
		return
	}
	writeJSON(response, http.StatusOK, sessionResponse{Session: sessionDetails{
		SubjectID: record.SubjectID,
		CreatedAt: record.CreatedAt,
		ExpiresAt: record.ExpiresAt,
	}})
}

func (handler *httpHandler) setSession(response http.ResponseWriter, token string, expiresAt time.Time) {
	cookie := handler.cookie
	cookie.Value = token
	cookie.Expires = expiresAt
	http.SetCookie(response, &cookie)
}

func (handler *httpHandler) validOrigin(origin string) bool {
	return origin != "" && slices.Contains(handler.allowedOrigins, origin)
}

func readCredentials(response http.ResponseWriter, request *http.Request) (credentialsRequest, bool) {
	var input credentialsRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return input, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return input, false
	}
	return input, true
}

func sourceKey(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil {
		return host
	}
	return request.RemoteAddr
}

func writeAuthenticationError(response http.ResponseWriter, err error) {
	if errors.Is(err, emailpassword.ErrInvalidInput) ||
		errors.Is(err, emailpassword.ErrInvalidPassword) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if errors.Is(err, emailpassword.ErrInvalidCredentials) {
		writeError(response, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if errors.Is(err, emailpassword.ErrRegistrationUnavailable) ||
		errors.Is(err, emailpassword.ErrConflict) {
		writeError(response, http.StatusConflict, "registration_unavailable")
		return
	}
	if errors.Is(err, emailpassword.ErrAttemptBlocked) {
		writeError(response, http.StatusTooManyRequests, "too_many_attempts")
		return
	}
	writeError(response, http.StatusInternalServerError, "authentication_failed")
}

func writeError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, errorResponse{Error: errorDetails{Code: code}})
}

func writeJSON(response http.ResponseWriter, status int, value interface{}) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
