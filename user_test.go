// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa_test

import (
	"os"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ubccr/goipa"
)

func addTestUser(c *ipa.Client, username, password string) (*ipa.User, error) {
	first := gofakeit.FirstName()
	last := gofakeit.LastName()
	rec, err := c.UserAdd(username, "", first, last, "", "", password != "")
	if err != nil {
		return nil, err
	}

	if password != "" {
		err = c.SetPassword(username, rec.RandomPassword, password, "")
		if err != nil {
			return nil, err
		}
	}

	return rec, nil
}

func TestUserShow(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	rec, err := c.UserShow(TestEnvAdminUser)
	require.NoError(err)

	assert.Equalf(TestEnvAdminUser, rec.Username, "User username invalid")
}

func TestUpdateSSHPubKeys(t *testing.T) {
	user := os.Getenv("GOIPA_TEST_USER")
	c, err := newTestClientUserPassword()
	require.NoError(t, err)

	// Remove any existing public keys
	fp, err := c.UpdateSSHPubKeys(user, []string{})
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			if ierr.Code != 4202 {
				t.Errorf("Failed to remove existing ssh public keys: %s", err)
			}
		} else {
			t.Errorf("Failed to remove existing ssh public keys: %s", err)
		}
	}

	if len(fp) != 0 {
		t.Error("Invalid number of fingerprints returned")
	}

	_, err = c.UpdateSSHPubKeys(user, []string{"invalid key"})
	if err == nil {
		t.Error("Invalid key was updated")
	}

	fp, err = c.UpdateSSHPubKeys(user, []string{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVBSs8RP8KPbdMwOmuKgjScx301k1mBZTubfcJc7HKcJ19f1Z/eJ5y9R7LjhsK1WGn8ISRtP2c0NUNPWcZHdWzTv6m2AFL4qniXr2vvKcewq2fxy8uXnUSvS054wwFDW6trmWV1Vrrab0eXO9S7tGGLdx2ySQ8Bzfe8wY3M2/N1gd5dzGSVg3qFspgikTKjRt5rfaWoN+/OWLDg1HHEWjY0Hgqry1bJW3U83SlIi9+JwKW0zxunwImgFsI1xC15lf7X9LOE9e6XGT1km/NTPOqoAvaCCA0KyAK7P6cLjFVAA/k9UnC/QX6JKXoURFRdhPEdFqauF3Xw9rwDFCFkMUp test@localhost"})
	if err != nil {
		t.Error(err)
	}

	if len(fp) != 1 {
		t.Errorf("Wrong number of fingerprints returned")
	}

	if fp[0] != "SHA256:9NiBLAynn/9d9lNcu/rOh5VXdXIJeA1oJDxfBGsI9xc test@localhost (ssh-rsa)" {
		t.Errorf("Invalid fingerprint: Got %s", fp[0])
	}

	// Remove test public keys
	_, err = c.UpdateSSHPubKeys(user, []string{})
	if err != nil {
		t.Error("Failed to remove testing ssh public keys")
	}
}

func TestUpdateMobile(t *testing.T) {
	user := os.Getenv("GOIPA_TEST_USER")
	c, err := newTestClientUserPassword()
	require.NoError(t, err)

	err = c.UpdateMobileNumber(user, "")
	if err != nil {
		t.Error("Failed to remove existing mobile number")
	}

	err = c.UpdateMobileNumber(user, "+9999999999")
	if err != nil {
		t.Error(err)
	}

	rec, err := c.UserShow(user)
	if err != nil {
		t.Error(err)
	}

	if string(rec.Mobile) != "+9999999999" {
		t.Errorf("Invalid mobile number")
	}
}

func TestUserAuthTypes(t *testing.T) {
	if len(os.Getenv("GOIPA_TEST_KEYTAB")) > 0 {
		c, err := newTestClientKeytab()
		require.NoError(t, err)

		user := os.Getenv("GOIPA_TEST_USER")

		err = c.SetAuthTypes(user, []string{"otp"})
		if err != nil {
			t.Error(err)
		}

		rec, err := c.UserShow(user)
		if err != nil {
			t.Error(err)
		}

		if !rec.OTPOnly() {
			t.Errorf("User auth type should only be OTP")
		}

		err = c.SetAuthTypes(user, nil)
		if err != nil {
			t.Error("Failed to remove existing auth types")
		}
	}
}

func TestUserAdd(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	username := gofakeit.Username()
	email := gofakeit.Email()
	first := gofakeit.FirstName()
	last := gofakeit.LastName()
	home := "/user/" + username
	shell := "/bin/bash"
	password := gofakeit.Password(true, true, true, true, false, 16)

	rec, err := c.UserAdd(username, email, first, last, home, shell, true)
	require.NoError(err)

	assert.Equalf(strings.ToLower(username), rec.Username, "User username invalid")
	assert.Equalf(email, rec.Email, "Email is invalid")
	assert.Equalf(first, rec.First, "First name is invalid")
	assert.Equalf(last, rec.Last, "Last name is invalid")
	assert.Equalf(home, rec.HomeDir, "Homedir is invalid")
	assert.Equalf(shell, rec.Shell, "Shell is invalid")

	err = c.SetPassword(username, rec.RandomPassword, password, "")
	assert.NoErrorf(err, "Failed to set password")

	userClient := ipa.NewDefaultClient()
	err = userClient.RemoteLogin(username, password)
	require.NoErrorf(err, "Failed to login as new user account")
	assert.NotEmptyf(c.SessionID(), "Missing sessionID for new user account")

	err = c.UserDelete(false, false, username)
	assert.NoErrorf(err, "Failed to remove user")
}

func TestUserLock(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	c, err := newTestClientCCache()
	require.NoError(err)

	username := gofakeit.Username()
	password := gofakeit.Password(true, true, true, true, false, 16)

	rec, err := addTestUser(c, username, password)
	require.NoErrorf(err, "Failed to add test user")

	assert.Falsef(rec.Locked, "Account should not be disabled")

	err = c.UserDisable(username)
	assert.NoErrorf(err, "Failed to disable user")

	rec, err = c.UserShow(username)
	require.NoErrorf(err, "Failed to show user")

	assert.Truef(rec.Locked, "Account should be locked")

	userClient := ipa.NewDefaultClient()
	err = userClient.RemoteLogin(username, password)
	assert.Errorf(err, "User should not be able to login")

	err = c.UserEnable(username)
	assert.NoErrorf(err, "Failed to enable user")

	rec, err = c.UserShow(username)
	require.NoErrorf(err, "Failed to show user")

	assert.Falsef(rec.Locked, "Account should not be disabled")

	userClient = ipa.NewDefaultClient()
	err = userClient.RemoteLogin(username, password)
	assert.NoErrorf(err, "User should be able to login")

	err = c.UserDelete(false, false, username)
	assert.NoErrorf(err, "Failed to remove user")
}
