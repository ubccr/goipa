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

	"github.com/ubccr/kerby/khttp"
)

const (
	IpaClientVersion  = "2.156"
	IpaDatetimeFormat = "20060102150405Z"
)

var (
	ipaCertPool       *x509.CertPool
	ipaSessionPattern = regexp.MustCompile(`^ipa_session=([^;]+);`)
)

// FreeIPA Client
type Client struct {
	Host    string
	CaCert  string
	KeyTab  string
	session string
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

// Set FreeIPA session id
func (c *Client) SetSession(sid string) {
	c.session = sid
}

// Clears out FreeIPA session id
func (c *Client) ClearSession() {
	c.session = ""
}

func (c *Client) rpc(method string, params []string, options map[string]interface{}) (*Response, error) {
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

	ipaUrl := fmt.Sprintf("https://%s/ipa/json", c.Host)
	if len(c.session) > 0 {
		ipaUrl = fmt.Sprintf("https://%s/ipa/session/json", c.Host)
	}

	req, err := http.NewRequest("POST", ipaUrl, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa", c.Host))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ipaCertPool}}

	client := &http.Client{Transport: tr}

	if len(c.session) > 0 {
		// If session is set, use the session id
		req.Header.Set("Cookie", fmt.Sprintf("ipa_session=%s", c.session))
	} else {
		// default to using Kerberos auth (SPNEGO)
		client.Transport = &khttp.Transport{Next: tr, KeyTab: c.KeyTab}
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("IPA RPC called failed with HTTP status code: %d", res.StatusCode)
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

// Login to FreeIPA with uid/passwd and set the FreeIPA session id on the
// client for subsequent requests.
func (c *Client) Login(uid, passwd string) (string, error) {
	ipaUrl := fmt.Sprintf("https://%s/ipa/session/login_password", c.Host)

	form := url.Values{"user": {uid}, "password": {passwd}}
	req, err := http.NewRequest("POST", ipaUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa", c.Host))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ipaCertPool}}
	client := &http.Client{Transport: tr}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return "", fmt.Errorf("IPA login failed with HTTP status code: %d", res.StatusCode)
	}

	cookie := res.Header.Get("Set-Cookie")
	if len(cookie) == 0 {
		return "", errors.New("ipa: login failed emtpy set-cookie header")
	}

	ipaSession := ""
	matches := ipaSessionPattern.FindStringSubmatch(cookie)
	if len(matches) == 2 {
		ipaSession = matches[1]
	}

	if len(ipaSession) == 32 || strings.HasPrefix(ipaSession, "MagBearerToken") {
		c.session = ipaSession
	} else {
		return "", errors.New("ipa: login failed invalid set-cookie header")
	}

	return ipaSession, nil
}
