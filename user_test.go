// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"os"
	"testing"
)

func TestRemoteLogin(t *testing.T) {
	host := os.Getenv("GOIPA_TEST_HOST")
	realm := os.Getenv("GOIPA_TEST_REALM")
	c := NewClient(host, realm)
	user := os.Getenv("GOIPA_TEST_USER")
	pass := os.Getenv("GOIPA_TEST_PASSWD")
	err := c.RemoteLogin(user, pass)
	if err != nil {
		t.Error(err)
	}

	sess := c.SessionID()

	if len(sess) == 0 {
		t.Error(err)
	}
}

func TestUserShow(t *testing.T) {
	user := os.Getenv("GOIPA_TEST_USER")
	c := newTestClientUserPassword()

	// Test using ipa_session
	rec, err := c.UserShow(user)

	if err != nil {
		t.Error(err)
	}

	if string(rec.Uid) != user {
		t.Errorf("Invalid user")
	}

	if len(os.Getenv("GOIPA_TEST_KEYTAB")) > 0 {
		c = newTestClientKeytab()

		// Test using keytab if set
		rec, err := c.UserShow(user)

		if err != nil || rec == nil {
			t.Error(err)
		}

		if string(rec.Uid) != user {
			t.Errorf("Invalid user")
		}
	}
}

func TestUpdateSSHPubKeys(t *testing.T) {
	user := os.Getenv("GOIPA_TEST_USER")
	c := newTestClientUserPassword()

	// Remove any existing public keys
	fp, err := c.UpdateSSHPubKeys(user, []string{})
	if err != nil {
		if ierr, ok := err.(*IpaError); ok {
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
	c := newTestClientUserPassword()

	err := c.UpdateMobileNumber(user, "")
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
		c := newTestClientKeytab()

		user := os.Getenv("GOIPA_TEST_USER")

		err := c.SetAuthTypes(user, []string{"otp"})
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
	if len(os.Getenv("GOIPA_TEST_KEYTAB")) > 0 && len(os.Getenv("GOIPA_TEST_USER_CREATE_UID")) > 0 {
		c := newTestClientKeytab()

		uid := os.Getenv("GOIPA_TEST_USER_CREATE_UID")
		email := os.Getenv("GOIPA_TEST_USER_CREATE_UID") + "@localhost.localdomain"
		first := "Mokey"
		last := "Test"
		homedir := ""
		shell := ""
		password := ""

		if len(os.Getenv("GOIPA_TEST_USER_CREATE_PASSWD")) > 0 {
			password = os.Getenv("GOIPA_TEST_USER_CREATE_PASSWD")
		}

		rec, err := c.UserAdd(uid, password, email, first, last, homedir, shell)
		if err != nil {
			t.Fatal(err)
		}

		if string(rec.Uid) != uid {
			t.Errorf("User uid invalid")
		}
	}
}
