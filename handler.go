package authlier

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Rahmannugar/authlier/emailpassword"
	"github.com/Rahmannugar/authlier/emailverification"
	"github.com/Rahmannugar/authlier/sessiontoken"
)

const maximumRequestBody = 1 << 20

type httpHandler struct {
	auth           *Auth
	allowedOrigins []string
	trustedProxies []netip.Prefix
	crossSitePOSTs map[string]struct{}
	cookie         http.Cookie
	sessionMode    SessionMode
	mux            *http.ServeMux
}

type credentialsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userDetails struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type userResponse struct {
	User    userDetails     `json:"user"`
	Session *sessionDetails `json:"session,omitempty"`
	Tokens  *tokenDetails   `json:"tokens,omitempty"`
}

type sessionResponse struct {
	Session sessionDetails `json:"session"`
	Tokens  *tokenDetails  `json:"tokens,omitempty"`
}

type tokenDetails struct {
	AccessToken           string    `json:"accessToken"`
	AccessTokenExpiresAt  time.Time `json:"accessTokenExpiresAt"`
	RefreshToken          string    `json:"refreshToken"`
	RefreshTokenExpiresAt time.Time `json:"refreshTokenExpiresAt"`
}

type sessionDetails struct {
	ID        string    `json:"id"`
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

func newHandler(
	auth *Auth,
	config Config,
	baseURL *url.URL,
	basePath string,
	accountBasePath string,
) (http.Handler, error) {
	sessionMode := config.Session.Mode
	if sessionMode == "" {
		sessionMode = SessionModeCookie
	}
	origins := []string{baseURL.Scheme + "://" + baseURL.Host}
	for _, rawOrigin := range config.TrustedOrigins {
		origin, err := url.Parse(strings.TrimSpace(rawOrigin))
		if err != nil || (origin.Scheme != "https" && origin.Scheme != "http") || origin.Host == "" ||
			origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
			return nil, fmt.Errorf("%w: invalid trusted origin", ErrInvalidConfig)
		}
		origins = append(origins, origin.Scheme+"://"+origin.Host)
	}
	trustedProxies, err := parseTrustedProxies(config.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid trusted proxy", ErrInvalidConfig)
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
	if sessionMode == SessionModeCookie &&
		cookie.SameSite == http.SameSiteNoneMode && baseURL.Scheme != "https" {
		return nil, fmt.Errorf("%w: SameSite=None requires HTTPS", ErrInvalidConfig)
	}
	auth.cookieName = cookie.Name
	handler := &httpHandler{
		auth:           auth,
		allowedOrigins: origins,
		trustedProxies: trustedProxies,
		crossSitePOSTs: make(map[string]struct{}),
		cookie: http.Cookie{
			Name:     cookie.Name,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			HttpOnly: true,
			Secure:   baseURL.Scheme == "https",
			SameSite: cookie.SameSite,
		},
		sessionMode: sessionMode,
		mux:         http.NewServeMux(),
	}
	if auth.password != nil {
		handler.mux.HandleFunc("POST "+basePath+"/sign-up", handler.signUp)
		handler.mux.HandleFunc("POST "+basePath+"/sign-in", handler.signIn)
		registerAccountRoutes(handler, basePath)
	}
	handler.mux.HandleFunc("POST "+basePath+"/sign-out", handler.signOut)
	handler.mux.HandleFunc("GET "+basePath+"/session", handler.session)
	registerSessionRoutes(handler, basePath)
	if auth.bearerSessions != nil {
		registerTokenRoutes(handler, basePath)
	}
	if auth.emailVerification != nil {
		registerEmailVerificationRoutes(handler, basePath)
	}
	if auth.passwordReset != nil {
		registerPasswordResetRoutes(handler, basePath)
	}
	if auth.totp != nil {
		registerTOTPRoutes(handler, basePath)
	}
	if auth.passkeys != nil {
		registerPasskeyRoutes(handler, basePath)
	}
	if auth.google != nil {
		registerGoogleRoutes(handler, basePath, accountBasePath)
	}
	if auth.oidc != nil || auth.saml != nil {
		registerSSORoutes(handler, basePath)
	}
	return handler, nil
}

func (handler *httpHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	origin := request.Header.Get("Origin")
	if origin != "" && handler.validOrigin(origin) {
		response.Header().Set("Access-Control-Allow-Origin", origin)
		if handler.sessionMode == SessionModeCookie {
			response.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		response.Header().Add("Vary", "Origin")
	}
	if request.Method == http.MethodOptions {
		if !handler.validOrigin(origin) {
			writeError(response, http.StatusForbidden, "origin_not_allowed")
			return
		}
		allowedHeaders := "Content-Type"
		if handler.sessionMode == SessionModeBearer {
			allowedHeaders += ", Authorization"
		}
		response.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
		response.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		response.WriteHeader(http.StatusNoContent)
		return
	}
	_, crossSitePOST := handler.crossSitePOSTs[request.URL.Path]
	if request.Method != http.MethodGet && !crossSitePOST {
		if origin != "" && !handler.validOrigin(origin) {
			writeError(response, http.StatusForbidden, "origin_not_allowed")
			return
		}
		if origin == "" && handler.sessionMode != SessionModeBearer {
			writeError(response, http.StatusForbidden, "origin_not_allowed")
			return
		}
	}
	handler.mux.ServeHTTP(response, request)
}

func (handler *httpHandler) signUp(response http.ResponseWriter, request *http.Request) {
	input, ok := readCredentials(response, request)
	if !ok {
		return
	}
	user, err := handler.auth.password.Register(request.Context(), emailpassword.RegisterInput{
		Email: input.Email, Password: input.Password, SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writeAuthenticationError(response, err)
		return
	}
	if handler.auth.emailVerification != nil &&
		(handler.auth.sendVerificationOnSignUp || handler.auth.requireEmailVerification) {
		if err := handler.auth.emailVerification.Request(request.Context(), emailverification.RequestInput{
			Email: user.Email, SourceKey: handler.sourceKey(request),
		}); err != nil {
			writeEmailVerificationError(response, err)
			return
		}
	}
	if handler.auth.requireEmailVerification {
		writeJSON(response, http.StatusCreated, newUserResponse(user.ID, user.Email))
		return
	}
	session, tokens, ok := handler.issueSession(response, request, user.ID)
	if !ok {
		return
	}
	writeJSON(response, http.StatusCreated, userResponse{
		User: userDetails{ID: user.ID, Email: user.Email}, Session: &session, Tokens: tokens,
	})
}

func (handler *httpHandler) signIn(response http.ResponseWriter, request *http.Request) {
	input, ok := readCredentials(response, request)
	if !ok {
		return
	}
	login, err := handler.auth.password.Login(request.Context(), emailpassword.LoginInput{
		Email: input.Email, Password: input.Password, SourceKey: handler.sourceKey(request),
	})
	if err != nil {
		writeAuthenticationError(response, err)
		return
	}
	if handler.auth.requireEmailVerification {
		verified, err := handler.auth.emailVerification.IsVerified(request.Context(), login.User.Email)
		if err != nil {
			writeError(response, http.StatusInternalServerError, "authentication_failed")
			return
		}
		if !verified {
			if handler.auth.sendVerificationOnSignIn {
				if err := handler.auth.emailVerification.Request(
					request.Context(),
					emailverification.RequestInput{Email: login.User.Email, SourceKey: handler.sourceKey(request)},
				); err != nil {
					writeEmailVerificationError(response, err)
					return
				}
			}
			writeError(response, http.StatusForbidden, "email_not_verified")
			return
		}
	}
	if handler.auth.totp != nil {
		enabled, err := handler.auth.totp.IsEnabled(request.Context(), login.User.ID)
		if err != nil {
			writeError(response, http.StatusInternalServerError, "authentication_failed")
			return
		}
		if enabled {
			challenge, err := handler.auth.totp.BeginChallenge(request.Context(), login.User.ID)
			if err != nil {
				writeError(response, http.StatusInternalServerError, "authentication_failed")
				return
			}
			writeJSON(response, http.StatusOK, twoFactorRequiredResponse{
				TwoFactorRequired: true,
				ChallengeToken:    challenge.Token,
				ExpiresAt:         challenge.ExpiresAt,
			})
			return
		}
	}
	session, tokens, ok := handler.issueSession(response, request, login.User.ID)
	if !ok {
		return
	}
	writeJSON(response, http.StatusOK, userResponse{
		User:    userDetails{ID: login.User.ID, Email: login.User.Email},
		Session: &session, Tokens: tokens,
	})
}

func (handler *httpHandler) signOut(response http.ResponseWriter, request *http.Request) {
	if handler.sessionMode == SessionModeBearer {
		session, err := handler.auth.ResolveSession(request)
		if err == nil {
			if err := handler.auth.bearerSessions.Revoke(request.Context(), session.ID); err != nil {
				writeError(response, http.StatusInternalServerError, "sign_out_failed")
				return
			}
			response.WriteHeader(http.StatusNoContent)
			return
		}
		if request.ContentLength != 0 {
			var input refreshTokenRequest
			if !readJSON(response, request, &input) {
				return
			}
			if err := handler.auth.bearerSessions.RevokeByRefreshToken(
				request.Context(),
				input.RefreshToken,
			); err != nil && !invalidRefreshTokenError(err) {
				writeError(response, http.StatusInternalServerError, "sign_out_failed")
				return
			}
		}
		response.WriteHeader(http.StatusNoContent)
		return
	}
	cookie, err := request.Cookie(handler.cookie.Name)
	if err == nil {
		if err := handler.auth.sessions.Revoke(request.Context(), cookie.Value); err != nil &&
			!errors.Is(err, sessiontoken.ErrNotFound) && !errors.Is(err, sessiontoken.ErrInvalidToken) {
			writeError(response, http.StatusInternalServerError, "sign_out_failed")
			return
		}
	}
	handler.clearSession(response)
	response.WriteHeader(http.StatusNoContent)
}

func (handler *httpHandler) clearSession(response http.ResponseWriter) {
	if handler.sessionMode != SessionModeCookie {
		return
	}
	expired := handler.cookie
	expired.Value = ""
	expired.MaxAge = -1
	expired.Expires = time.Unix(1, 0)
	http.SetCookie(response, &expired)
}

func (handler *httpHandler) session(response http.ResponseWriter, request *http.Request) {
	record, err := handler.auth.ResolveSession(request)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "not_authenticated")
		return
	}
	writeJSON(response, http.StatusOK, sessionResponse{Session: newSessionDetails(record)})
}

func (handler *httpHandler) setSession(response http.ResponseWriter, token string, expiresAt time.Time) {
	cookie := handler.cookie
	cookie.Value = token
	cookie.Expires = expiresAt
	http.SetCookie(response, &cookie)
}

func newSessionDetails(record Session) sessionDetails {
	return sessionDetails{
		ID:        record.ID,
		SubjectID: record.SubjectID,
		CreatedAt: record.CreatedAt,
		ExpiresAt: record.ExpiresAt,
	}
}

func (handler *httpHandler) completeProviderAuthentication(
	response http.ResponseWriter,
	request *http.Request,
	subjectID string,
	redirectURL string,
) {
	if redirectURL != "" && handler.sessionMode == SessionModeBearer {
		writeError(response, http.StatusBadRequest, "token_redirect_not_supported")
		return
	}
	session, tokens, ok := handler.issueSession(response, request, subjectID)
	if !ok {
		return
	}
	if redirectURL != "" {
		http.Redirect(response, request, redirectURL, http.StatusSeeOther)
		return
	}
	writeJSON(response, http.StatusOK, sessionResponse{Session: session, Tokens: tokens})
}

func (handler *httpHandler) createAuthenticatedSession(
	response http.ResponseWriter,
	request *http.Request,
	subjectID string,
) {
	session, tokens, ok := handler.issueSession(response, request, subjectID)
	if !ok {
		return
	}
	writeJSON(response, http.StatusOK, sessionResponse{Session: session, Tokens: tokens})
}

func (handler *httpHandler) issueSession(
	response http.ResponseWriter,
	request *http.Request,
	subjectID string,
) (sessionDetails, *tokenDetails, bool) {
	if handler.sessionMode == SessionModeBearer {
		issued, err := handler.auth.bearerSessions.Create(request.Context(), subjectID)
		if err != nil {
			writeError(response, http.StatusInternalServerError, "session_failed")
			return sessionDetails{}, nil, false
		}
		return newSessionDetails(issued.Session), newTokenDetails(issued), true
	}
	issued, err := handler.auth.sessions.Create(request.Context(), subjectID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "session_failed")
		return sessionDetails{}, nil, false
	}
	handler.setSession(response, issued.Token, issued.Record.ExpiresAt)
	return newSessionDetails(Session{
		ID: issued.Record.ID, SubjectID: issued.Record.SubjectID,
		CreatedAt: issued.Record.CreatedAt, ExpiresAt: issued.Record.ExpiresAt,
	}), nil, true
}

func newTokenDetails(issued bearerSessionIssued) *tokenDetails {
	return &tokenDetails{
		AccessToken: issued.AccessToken, AccessTokenExpiresAt: issued.AccessTokenExpiresAt,
		RefreshToken: issued.RefreshToken, RefreshTokenExpiresAt: issued.RefreshTokenExpiresAt,
	}
}

func (handler *httpHandler) requireSession(
	response http.ResponseWriter,
	request *http.Request,
	fresh bool,
) (Session, bool) {
	record, err := handler.auth.ResolveSession(request)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "not_authenticated")
		return Session{}, false
	}
	if fresh && time.Now().UTC().After(record.CreatedAt.Add(handler.auth.sessionFreshAge)) {
		writeError(response, http.StatusForbidden, "recent_authentication_required")
		return Session{}, false
	}
	return record, true
}

func (handler *httpHandler) validOrigin(origin string) bool {
	return origin != "" && slices.Contains(handler.allowedOrigins, origin)
}

func readCredentials(response http.ResponseWriter, request *http.Request) (credentialsRequest, bool) {
	var input credentialsRequest
	if !readJSON(response, request, &input) {
		return input, false
	}
	return input, true
}

func readJSON(response http.ResponseWriter, request *http.Request, destination interface{}) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func parseTrustedProxies(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, err
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func (handler *httpHandler) sourceKey(request *http.Request) string {
	peer, ok := remoteAddress(request.RemoteAddr)
	if !ok {
		return request.RemoteAddr
	}
	peer = peer.Unmap()
	if !handler.trustedProxy(peer) {
		return peer.String()
	}

	forwarded := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
	candidate := peer
	for index := len(forwarded) - 1; index >= 0; index-- {
		address, err := netip.ParseAddr(strings.TrimSpace(forwarded[index]))
		if err != nil {
			return peer.String()
		}
		candidate = address.Unmap()
		if !handler.trustedProxy(candidate) {
			return candidate.String()
		}
	}
	return candidate.String()
}

func remoteAddress(value string) (netip.Addr, bool) {
	if addressPort, err := netip.ParseAddrPort(value); err == nil {
		return addressPort.Addr(), true
	}
	address, err := netip.ParseAddr(value)
	return address, err == nil
}

func (handler *httpHandler) trustedProxy(address netip.Addr) bool {
	for _, prefix := range handler.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
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

func newUserResponse(id, email string) userResponse {
	return userResponse{User: userDetails{ID: id, Email: email}}
}
