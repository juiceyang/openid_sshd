package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
)

const (
	CLIENT_ID          = "pseudo-client-id"
	CLIENT_SECRET      = "pseudo-client-secret"
	OIDC_SERVER_IP     = "localhost"
	OIDC_SERVER_PORT   = 8000
	OIDC_CALLBACK_PATH = "/oidc/callback"
	OIDC_SCOPE         = "openid email"
)

var (
	rootUrl            = "pseudo-root-url"
	authorizeEndpoint  = fmt.Sprintf("%v/authorize", rootUrl)
	responseType       = "code"
	tokenEndpoint      = fmt.Sprintf("%v/token", rootUrl)
	grantType          = "authorization_code"
	introspectEndpoint = fmt.Sprintf("%v/introspect", rootUrl)
	redirectUri        = fmt.Sprintf("http://%v:%v%v", OIDC_SERVER_IP, OIDC_SERVER_PORT, OIDC_CALLBACK_PATH)
)

type IntrospectResp struct {
	Active    bool   `json:"active"`
	Aud       string `json:"aud"`
	ClientId  string `json:"client_id"`
	DeviceId  string `json:"device_id"`
	Exp       int    `json:"exp"`
	Iat       int    `json:"iat"`
	Iss       string `json:"iss"`
	Jti       string `json:"jti"`
	Nbf       string `json:"nbf"`
	Scope     string `json:"scope"`
	Sub       string `json:"sub"`
	TokenType string `json:"token_type"`
	Uid       string `json:"uid"`
	Username  string `json:"username"`
	State     string
}

func generateState() string {
	return fmt.Sprintf("%x", rand.Int())
}

func generateAuthorizeUrl() (*url.URL, string, error) {
	state := generateState()
	q := url.Values{}
	q.Set("response_type", responseType)
	q.Set("client_id", CLIENT_ID)
	q.Set("redirect_uri", redirectUri)
	q.Set("state", state)
	q.Set("scope", OIDC_SCOPE)
	u, err := url.Parse(authorizeEndpoint)
	if err != nil {
		return u, state, err
	}
	u.RawQuery = q.Encode()
	return u, state, nil
}

func generateTokenUrl(code string) (*url.URL, error) {
	q := url.Values{}
	q.Set("grant_type", "authorization_code")
	q.Set("code", code)
	q.Set("redirect_uri", redirectUri)
	q.Set("client_id", CLIENT_ID)
	q.Set("client_secret", CLIENT_SECRET)
	u, err := url.Parse(tokenEndpoint)
	if err != nil {
		return u, err
	}
	u.RawQuery = q.Encode()
	return u, nil
}

func generateIntrospectUrl(accessToken string) (*url.URL, error) {
	q := url.Values{}
	q.Set("token", accessToken)
	q.Set("client_id", CLIENT_ID)
	q.Set("client_secret", CLIENT_SECRET)
	u, err := url.Parse(introspectEndpoint)
	if err != nil {
		return u, err
	}
	u.RawQuery = q.Encode()
	return u, nil
}

func authorizeIntrospect(intro IntrospectResp) {
}

func handleOidcCallback(resp http.ResponseWriter, req *http.Request) {
	fmt.Printf("Handling request from %v\n", req.RemoteAddr)
	values := req.URL.Query()
	code := values.Get("code")
	state := values.Get("state")
	tokenUrl, err := generateTokenUrl(code)
	if err != nil {
		panic(err)
	}
	tokenResp, err := http.Post(tokenUrl.String(), "application/x-www-form-urlencoded", nil)
	if err != nil {
		panic(err)
	}
	defer tokenResp.Body.Close()
	body, err := ioutil.ReadAll(tokenResp.Body)
	if err != nil {
		panic(err)
	}
	tokenRespJson := make(map[string]string)
	json.Unmarshal(body, &tokenRespJson)
	accessToken := tokenRespJson["access_token"]
	introspectUrl, err := generateIntrospectUrl(accessToken)
	if err != nil {
		panic(err)
	}
	introspectResp, err := http.Post(introspectUrl.String(), "application/x-www-form-urlencoded", nil)
	if err != nil {
		panic(err)
	}
	body, err = ioutil.ReadAll(introspectResp.Body)
	if err != nil {
		panic(err)
	}
	var intro IntrospectResp
	json.Unmarshal(body, &intro)
	intro.State = state
	openIDCh <- intro
}

func httpListenAndServe() {
	http.HandleFunc(OIDC_CALLBACK_PATH, handleOidcCallback)
	addr := fmt.Sprintf("%v:%v", OIDC_SERVER_IP, OIDC_SERVER_PORT)
	fmt.Printf("OpenID HTTP server listening: %v\n", addr)
	http.ListenAndServe(
		addr,
		nil,
	)
}
