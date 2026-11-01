// Package oidctest is a fake OIDC provider for tests. It serves discovery, JWKS, an authorize
// endpoint that answers at once, and a token endpoint that checks PKCE. It uses no network.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// ClientID is the only client the fake provider knows.
	ClientID = "client-for-tests"
	// ClientSecret is the secret of ClientID.
	ClientSecret = "client-secret-for-tests"

	keyID = "test-key"
)

// grant is one authorization that waits for its code exchange.
type grant struct {
	redirectURI string
	challenge   string
	nonce       string
	subject     string
}

// Provider is the fake provider. The zero value is not usable: call New.
type Provider struct {
	server        *httptest.Server
	key           *rsa.PrivateKey
	discoveryDown atomic.Bool
	mu            sync.Mutex
	subject       string
	claims        map[string]any
	grants        map[string]grant
}

// New starts a provider that closes with the test.
func New(t *testing.T) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{key: key, grants: map[string]grant{}, claims: map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// Issuer is the issuer URL.
func (p *Provider) Issuer() string {
	return p.server.URL
}

// SetSubject sets the `sub` of the next authorization.
func (p *Provider) SetSubject(subject string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subject = subject
}

// SetClaim makes the next ID tokens carry value as the claim name, in place of the true value.
func (p *Provider) SetClaim(name string, value any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.claims[name] = value
}

// ResetClaims makes the next ID tokens carry the true claims again.
func (p *Provider) ResetClaims() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.claims)
}

// SetDiscoveryDown makes discovery answer 503 while down is true.
func (p *Provider) SetDiscoveryDown(down bool) {
	p.discoveryDown.Store(down)
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	if p.discoveryDown.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.Issuer(),
		"authorization_endpoint":                p.Issuer() + "/authorize",
		"token_endpoint":                        p.Issuer() + "/token",
		"jwks_uri":                              p.Issuer() + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize grants at once and sends the browser back with a code and the state.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := rand.Text()
	p.mu.Lock()
	p.grants[code] = grant{
		redirectURI: q.Get("redirect_uri"),
		challenge:   q.Get("code_challenge"),
		nonce:       q.Get("nonce"),
		subject:     p.subject,
	}
	p.mu.Unlock()
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	values := back.Query()
	values.Set("code", code)
	values.Set("state", q.Get("state"))
	back.RawQuery = values.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound) // #nosec G710 -- the fake provider trusts every test client.
}

// token checks the client, the code, the redirect URI, and the PKCE verifier, then signs an ID token.
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != ClientID || secret != ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	p.mu.Lock()
	g, found := p.grants[r.PostForm.Get("code")]
	delete(p.grants, r.PostForm.Get("code"))
	claims := map[string]any{}
	for name, value := range p.claims {
		claims[name] = value
	}
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || g.redirectURI != r.PostForm.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	issued := map[string]any{
		"iss":   p.Issuer(),
		"aud":   ClientID,
		"sub":   g.subject,
		"nonce": g.nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	for name, value := range claims {
		issued[name] = value
	}
	idToken, err := p.sign(issued)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": rand.Text(),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (p *Provider) sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("oidctest: header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("oidctest: claims: %w", err)
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("oidctest: sign: %w", err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
