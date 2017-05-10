// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// UserRecord encapsulates user data returned from ipa user commands
type UserRecord struct {
	Dn               string      `json:"dn"`
	First            IpaString   `json:"givenname"`
	Last             IpaString   `json:"sn"`
	DisplayName      IpaString   `json:"displayname"`
	Principal        IpaString   `json:"krbprincipalname"`
	Uid              IpaString   `json:"uid"`
	UidNumber        IpaString   `json:"uidnumber"`
	GidNumber        IpaString   `json:"gidnumber"`
	Groups           []string    `json:"memberof_group"`
	SSHPubKeys       []string    `json:"ipasshpubkey"`
	SSHPubKeyFps     []string    `json:"sshpubkeyfp"`
	AuthTypes        []string    `json:"ipauserauthtype"`
	HasKeytab        bool        `json:"has_keytab"`
	HasPassword      bool        `json:"has_password"`
	Locked           bool        `json:"nsaccountlock"`
	HomeDir          IpaString   `json:"homedirectory"`
	Email            IpaString   `json:"mail"`
	Mobile           IpaString   `json:"mobile"`
	Shell            IpaString   `json:"loginshell"`
	SudoRules        IpaString   `json:"memberofindirect_sudorule"`
	HbacRules        IpaString   `json:"memberofindirect_hbacrule"`
	LastPasswdChange IpaDateTime `json:"krblastpwdchange"`
	PasswdExpire     IpaDateTime `json:"krbpasswordexpiration"`
	PrincipalExpire  IpaDateTime `json:"krbprincipalexpiration"`
	LastLoginSuccess IpaDateTime `json:"krblastsuccessfulauth"`
	LastLoginFail    IpaDateTime `json:"krblastfailedauth"`
	Randompassword   string      `json:"randompassword"`
}

// Returns true if Two-Factor authentication is the only authentication type
func (u *UserRecord) TwoFactorOnly() bool {
	if len(u.AuthTypes) == 1 && u.AuthTypes[0] == "otp" {
		return true
	}

	return false
}

// Returns true if the User is in group
func (u *UserRecord) HasGroup(group string) bool {
	for _, g := range u.Groups {
		if g == group {
			return true
		}
	}

	return false
}

// Fetch user details by call the FreeIPA user-show method
func (c *Client) UserShow(uid string) (*UserRecord, error) {

	options := map[string]interface{}{
		"no_members": false,
		"all":        true}

	res, err := c.rpc("user_show", []string{uid}, options)

	if err != nil {
		return nil, err
	}

	var userRec UserRecord
	err = json.Unmarshal(res.Result.Data, &userRec)
	if err != nil {
		return nil, err
	}

	return &userRec, nil
}

// Update ssh public keys for user uid. Returns the fingerprints on success.
func (c *Client) UpdateSSHPubKeys(uid string, keys []string) ([]string, error) {
	options := map[string]interface{}{
		"no_members":   false,
		"ipasshpubkey": keys,
		"all":          false}

	res, err := c.rpc("user_mod", []string{uid}, options)

	if err != nil {
		return nil, err
	}

	var userRec UserRecord
	err = json.Unmarshal(res.Result.Data, &userRec)
	if err != nil {
		return nil, err
	}

	return userRec.SSHPubKeyFps, nil
}

// Update mobile number. Currently will store only a single number. Any
// existing numbers will be overwritten.
func (c *Client) UpdateMobileNumber(uid string, number string) error {
	options := map[string]interface{}{
		"no_members": false,
		"mobile":     []string{number},
		"all":        false}

	_, err := c.rpc("user_mod", []string{uid}, options)

	if err != nil {
		return err
	}

	return nil
}

// Reset user password and return new random password
func (c *Client) ResetPassword(uid string) (string, error) {

	options := map[string]interface{}{
		"no_members": false,
		"random":     true,
		"all":        true}

	res, err := c.rpc("user_mod", []string{uid}, options)

	if err != nil {
		return "", err
	}

	var userRec UserRecord
	err = json.Unmarshal(res.Result.Data, &userRec)
	if err != nil {
		return "", err
	}

	if len(userRec.Randompassword) == 0 {
		return "", errors.New("ipa: failed to reset user password. empty random password returned")
	}

	return userRec.Randompassword, nil
}

// Change users password
func (c *Client) ChangePassword(uid, old_passwd, new_passwd string) error {
	ipaUrl := fmt.Sprintf("https://%s/ipa/session/change_password", c.Host)

	form := url.Values{
		"user":         {uid},
		"old_password": {old_passwd},
		"new_password": {new_passwd}}
	req, err := http.NewRequest("POST", ipaUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa", c.Host))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ipaCertPool}}
	client := &http.Client{Transport: tr}

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("ipa: change password failed with HTTP status code: %d", res.StatusCode)
	}

	status := res.Header.Get("x-ipa-pwchange-result")
	if status == "policy-error" {
		return &ErrPasswordPolicy{}
	} else if status == "invalid-password" {
		return &ErrInvalidPassword{}
	} else if strings.ToLower(status) != "ok" {
		return errors.New("ipa: change password failed. Unknown status")
	}

	return nil
}

// Remove TOTP token
func (c *Client) RemoveOTPToken(uid string) error {
	options := map[string]interface{}{}

	_, err := c.rpc("otptoken_del", []string{uid}, options)

	if err != nil {
		return err
	}

	return nil
}

// Add TOTP token. Returns the TOTP URI
func (c *Client) AddTOTPToken(uid string, algo Algorithm, digits Digits, interval int) (string, error) {

	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	options := map[string]interface{}{
		"type": "totp",
		"ipatokenotpkey": map[string]interface{}{
			"__base64__": base64.StdEncoding.EncodeToString(secret),
		},
		"ipatokenotpalgorithm": strings.ToLower(string(algo)),
		"ipatokenotpdigits":    digits,
		"ipatokentotptimestep": interval,
		"no_qrcode":            true,
		"qrcode":               false,
		"no_members":           false,
		"all":                  false}

	res, err := c.rpc("otptoken_add", []string{uid}, options)

	if err != nil {
		return "", err
	}

	var rec map[string]interface{}
	err = json.Unmarshal(res.Result.Data, &rec)
	if err != nil {
		return "", err
	}

	val, ok := rec["uri"]
	if !ok {
		return "", errors.New("URI was not returned from FreeIPA")
	}

	uri, ok := val.(string)

	if !ok || len(uri) == 0 {
		return "", errors.New("Invalid URI was returned from FreeIPA")
	}

	return uri, nil
}
