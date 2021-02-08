// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

// Package ipa is a Go client library for FreeIPA
package ipa

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-ini/ini"
	"gopkg.in/jcmturner/gokrb5.v6/client"
	"gopkg.in/jcmturner/gokrb5.v6/config"
	"gopkg.in/jcmturner/gokrb5.v6/keytab"
)

const (
	IpaClientVersion  = "2.156"
	IpaDatetimeFormat = "20060102150405Z"
)

var (
	ipaDefaultHost    string
	ipaDefaultRealm   string
	ipaCertPool       *x509.CertPool
	ipaSessionPattern = regexp.MustCompile(`^ipa_session=([^;]+);`)
)

// FreeIPA Client
type Client struct {
	host       string
	realm      string
	keyTab     string
	sessionID  string
	sticky     bool
	httpClient *http.Client
	krbClient  *client.Client
}

// FreeIPA Password Policy Error
type ErrPasswordPolicy struct {
}

func (e *ErrPasswordPolicy) Error() string {
	return "ipa: password does not conform to policy"
}

// FreeIPA Invalid Password Error
type ErrInvalidPassword struct {
}

func (e *ErrInvalidPassword) Error() string {
	return "ipa: invalid current password"
}

// FreeIPA error
type IpaError struct {
	Message string
	Code    int
}

// Custom FreeIPA string type
type IpaString string

// Custom FreeIPA datetime type
type IpaDateTime time.Time

// Result returned from a FreeIPA JSON rpc call
type Result struct {
	Summary string          `json:"summary"`
	Value   interface{}     `json:"value"`
	Data    json.RawMessage `json:"result"`
}

// Response returned from a FreeIPA JSON rpc call
type Response struct {
	Error     *IpaError `json:"error"`
	Id        string    `json:"id"`
	Principal string    `json:"principal"`
	Version   string    `json:"version"`
	Result    *Result   `json:"result"`
}

func init() {
	// If ca.crt for ipa exists, use it as the cert pool
	// otherwise default to system root ca.
	pem, err := ioutil.ReadFile("/etc/ipa/ca.crt")
	if err == nil {
		ipaCertPool = x509.NewCertPool()
		if !ipaCertPool.AppendCertsFromPEM(pem) {
			ipaCertPool = nil
		}
	}

	// Load default IPA host
	cfg, err := ini.Load("/etc/ipa/default.conf")
	if err == nil {
		ipaDefaultHost = cfg.Section("global").Key("host").MustString("localhost")
		ipaDefaultRealm = cfg.Section("global").Key("realm").MustString("LOCAL")
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 1 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: ipaCertPool},
		},
	}
}

// New default IPA Client using host and realm from /etc/ipa/default.conf
func NewDefaultClient() *Client {
	return &Client{
		host:       ipaDefaultHost,
		realm:      ipaDefaultRealm,
		sticky:     true,
		httpClient: newHTTPClient(),
	}
}

// New default IPA Client with existing sessionID using host and realm from /etc/ipa/default.conf
func NewDefaultClientWithSession(sessionID string) *Client {
	return &Client{
		host:       ipaDefaultHost,
		realm:      ipaDefaultRealm,
		httpClient: newHTTPClient(),
		sticky:     true,
		sessionID:  sessionID,
	}
}

// New IPA Client with host and realm
func NewClient(host, realm string) *Client {
	return &Client{
		host:       host,
		realm:      realm,
		sticky:     true,
		httpClient: newHTTPClient(),
	}
}

// New IPA Client with host, realm and custom http client
func NewClientCustomHttp(host, realm string, httpClient *http.Client) *Client {
	return &Client{
		host:       host,
		realm:      realm,
		sticky:     true,
		httpClient: httpClient,
	}
}

// Unmarshal a FreeIPA datetime. Datetimes in FreeIPA are returned using a
// class-hint system. Values are stored as an array with a single element
// indicating the type and value, for example, '[{"__datetime__": "YYYY-MM-DDTHH:MM:SSZ"]}'
func (dt *IpaDateTime) UnmarshalJSON(b []byte) error {
	var a []map[string]string
	err := json.Unmarshal(b, &a)
	if err != nil {
		return err
	}

	if len(a) == 0 {
		return nil
	}

	if str, ok := a[0]["__datetime__"]; ok {
		t, err := time.Parse(IpaDatetimeFormat, str)
		if err != nil {
			return err
		}
		*dt = IpaDateTime(t)
	}

	return nil
}

func (dt *IpaDateTime) UnmarshalBinary(data []byte) error {
	t := time.Time(*dt)
	err := t.UnmarshalBinary(data)
	if err != nil {
		return err
	}

	*dt = IpaDateTime(t)
	return nil
}

func (dt *IpaDateTime) MarshalBinary() (data []byte, err error) {
	return time.Time(*dt).MarshalBinary()
}

func (dt *IpaDateTime) String() string {
	return time.Time(*dt).String()
}

func (dt *IpaDateTime) Format(layout string) string {
	return time.Time(*dt).Format(layout)
}

// Unmarshal a FreeIPA string from an array of strings. Uses the first value
// in the array as the value of the string.
func (s *IpaString) UnmarshalJSON(b []byte) error {
	var a []string
	err := json.Unmarshal(b, &a)
	if err != nil {
		return err
	}

	if len(a) > 0 {
		*s = IpaString(a[0])
	}

	return nil
}

func (s *IpaString) String() string {
	return string(*s)
}

func (e *IpaError) Error() string {
	return fmt.Sprintf("ipa: error %d - %s", e.Code, e.Message)
}

// Call FreeIPA API with method, params and options
func (c *Client) rpc(method string, params []string, options map[string]interface{}) (*Response, error) {
	if options == nil {
		options = map[string]interface{}{}
	}

	options["version"] = IpaClientVersion

	var data []interface{} = make([]interface{}, 2)
	data[0] = params
	data[1] = options
	payload := map[string]interface{}{
		"method": method,
		"params": data}

	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	ipaUrl := fmt.Sprintf("https://%s/ipa/json", c.host)
	if len(c.sessionID) > 0 {
		ipaUrl = fmt.Sprintf("https://%s/ipa/session/json", c.host)
	}

	req, err := http.NewRequest("POST", ipaUrl, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa", c.host))

	if len(c.sessionID) > 0 {
		// If session is set, use the session id
		req.Header.Set("Cookie", fmt.Sprintf("ipa_session=%s", c.sessionID))
	} else if c.krbClient != nil {
		// use Kerberos auth (SPNEGO)
		c.krbClient.SetSPNEGOHeader(req, "")
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("IPA RPC called failed with HTTP status code: %d", res.StatusCode)
	}

	if err = c.setSessionID(res); err != nil {
		return nil, err
	}

	// XXX use the stream decoder here instead of reading entire body?
	//decoder := json.NewDecoder(res.Body)
	rawJson, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var ipaRes Response
	err = json.Unmarshal(rawJson, &ipaRes)
	if err != nil {
		return nil, err
	}

	if ipaRes.Error != nil {
		return nil, ipaRes.Error
	}

	return &ipaRes, nil
}

// Ping FreeIPA server to check connection
func (c *Client) Ping() (*Response, error) {
	options := map[string]interface{}{}

	res, err := c.rpc("ping", []string{}, options)

	if err != nil {
		return nil, err
	}

	return res, nil
}

// Return current FreeIPA sessionID
func (c *Client) SessionID() string {
	return c.sessionID
}

// Clears out FreeIPA session id
func (c *Client) ClearSession() {
	c.sessionID = ""
}

// Set stick sessions.
func (c *Client) StickySession(enable bool) {
	c.sticky = enable
}

// Set FreeIPA sessionID from http response cookie
func (c *Client) setSessionID(res *http.Response) error {
	if !c.sticky {
		return nil
	}

	cookie := res.Header.Get("Set-Cookie")
	if len(cookie) == 0 {
		return nil
	}

	ipaSession := ""
	matches := ipaSessionPattern.FindStringSubmatch(cookie)
	if len(matches) == 2 {
		ipaSession = matches[1]
	}

	if len(ipaSession) == 32 || strings.HasPrefix(ipaSession, "MagBearerToken") {
		c.sessionID = ipaSession
	} else {
		return errors.New("invalid set-cookie header")
	}

	return nil
}

// Login to FreeIPA using web API with uid/passwd and set the FreeIPA session
// id on the client for subsequent requests.
func (c *Client) RemoteLogin(uid, passwd string) error {
	ipaUrl := fmt.Sprintf("https://%s/ipa/session/login_password", c.host)

	form := url.Values{"user": {uid}, "password": {passwd}}
	req, err := http.NewRequest("POST", ipaUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa", c.host))

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("IPA login failed with HTTP status code: %d", res.StatusCode)
	}

	if err = c.setSessionID(res); err != nil {
		return err
	}

	return nil
}

// Login to FreeIPA using local kerberos login username and password
func (c *Client) Login(username, password string) error {
	cfg, err := config.Load("/etc/krb5.conf")
	if err != nil {
		return err
	}

	cl := client.NewClientWithPassword(username, c.realm, password)
	cl.WithConfig(cfg)

	err = cl.Login()
	if err != nil {
		return err
	}

	c.krbClient = &cl

	return nil
}

// Login to FreeIPA using local kerberos login with keytab and username
func (c *Client) LoginWithKeytab(ktab, username string) error {
	cfg, err := config.Load("/etc/krb5.conf")
	if err != nil {
		return err
	}

	kt, err := keytab.Load(ktab)
	if err != nil {
		return err
	}

	cl := client.NewClientWithKeytab(username, c.realm, kt)
	cl.WithConfig(cfg)

	err = cl.Login()
	if err != nil {
		return err
	}

	c.krbClient = &cl

	return nil
}
