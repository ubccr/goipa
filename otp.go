// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"fmt"

	"encoding/json"
	"strings"
)

// OTP Token hash Algorithms supported by FreeIPA
type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256           = "SHA256"
	AlgorithmSHA384           = "SHA384"
	AlgorithmSHA512           = "SHA512"
)

// Number of digits each OTP token code will have
type Digits int

const (
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

// OTPToken encapsulates FreeIPA otptokens
type OTPToken struct {
	DN        string    `json:"dn"`
	Algorithm Algorithm `json:"ipatokenotpalgorithm"`
	Digits    Digits    `json:"ipatokenotpdigits"`
	Owner     string    `json:"ipatokenowner"`
	TimeStep  string    `json:"ipatokentotptimestep"`
	UUID      string    `json:"ipatokenuniqueid"`
	ManagedBy string    `json:"managedby_user"`
	Disabled  string    `json:"ipatokendisabled"`
	Type      string    `json:"type"`
	URI       string    `json:"uri"`
}

func (t *OTPToken) Enabled() bool {
	if t.Disabled == "TRUE" {
		return false
	}

	return true
}

// Unmarshal a FreeIPA string from an array of strings and convert to an
// Algorithm. Uses the first value in the array as the value of the string.
func (a *Algorithm) UnmarshalJSON(b []byte) error {
	var values []string
	err := json.Unmarshal(b, &values)
	if err != nil {
		return err
	}

	algo := ""

	if len(values) > 0 {
		algo = values[0]
	}

	switch algo {
	case "sha1":
		*a = AlgorithmSHA1
	case "sha256":
		*a = AlgorithmSHA256
	case "sha384":
		*a = AlgorithmSHA384
	case "sha512":
		*a = AlgorithmSHA512
	default:
		*a = AlgorithmSHA1
	}

	return nil
}

func (a *Algorithm) String() string {
	return string(*a)
}

// Unmarshal a FreeIPA string from an array of strings and convert to Digits.
// Uses the first value in the array as the value of the string.
func (d *Digits) UnmarshalJSON(b []byte) error {
	var values []string
	err := json.Unmarshal(b, &values)
	if err != nil {
		return err
	}

	digi := ""

	if len(values) > 0 {
		digi = values[0]
	}

	switch digi {
	case "6":
		*d = DigitsSix
	case "8":
		*d = DigitsEight
	default:
		*d = DigitsSix
	}

	return nil
}

func (d *Digits) String() string {
	return fmt.Sprint(*d)
}

// Remove OTP token
func (c *Client) RemoveOTPToken(tokenID string) error {
	options := map[string]interface{}{}

	_, err := c.rpc("otptoken_del", []string{tokenID}, options)

	if err != nil {
		return err
	}

	return nil
}

// Fetch all OTP tokens.
func (c *Client) FetchOTPTokens(uid string) ([]*OTPToken, error) {
	options := map[string]interface{}{
		"ipatokenowner": uid,
		"all":           true}

	res, err := c.rpc("otptoken_find", []string{}, options)

	if err != nil {
		return nil, err
	}

	var tokens []*OTPToken
	err = json.Unmarshal(res.Result.Data, &tokens)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// Add TOTP token. Returns new OTPToken
func (c *Client) AddTOTPToken(uid string, algo Algorithm, digits Digits, interval int) (*OTPToken, error) {
	options := map[string]interface{}{
		"type":                 "totp",
		"ipatokenotpalgorithm": strings.ToLower(string(algo)),
		"ipatokenotpdigits":    digits,
		"ipatokentotptimestep": interval,
		"ipatokenowner":        uid,
		"no_qrcode":            true,
		"qrcode":               false,
		"no_members":           false,
		"all":                  true}

	res, err := c.rpc("otptoken_add", []string{}, options)

	if err != nil {
		return nil, err
	}

	var tokenRec OTPToken
	err = json.Unmarshal(res.Result.Data, &tokenRec)
	if err != nil {
		return nil, err
	}

	return &tokenRec, nil
}

// Enable OTP token.
func (c *Client) EnableOTPToken(tokenID string) error {
	options := map[string]interface{}{
		"ipatokendisabled": false,
		"all":              false}

	_, err := c.rpc("otptoken_mod", []string{tokenID}, options)

	return err
}

// Disable OTP token.
func (c *Client) DisableOTPToken(tokenID string) error {
	options := map[string]interface{}{
		"ipatokendisabled": true,
		"all":              false}

	_, err := c.rpc("otptoken_mod", []string{tokenID}, options)

	return err
}
