// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"os"
	"testing"
)

func newClient() *Client {
	host := os.Getenv("GOIPA_TEST_HOST")
	keytab := os.Getenv("GOIPA_TEST_KEYTAB")

	return &Client{KeyTab: keytab, Host: host}
}

func TestLogin(t *testing.T) {
	c := newClient()
	user := os.Getenv("GOIPA_TEST_USER")
	pass := os.Getenv("GOIPA_TEST_PASSWD")
	sess, err := c.Login(user, pass)
	if err != nil {
		t.Error(err)
	}

	if len(sess) == 0 {
		t.Error(err)
	}
}

func TestUserShow(t *testing.T) {
	c := newClient()

	user := os.Getenv("GOIPA_TEST_USER")
	pass := os.Getenv("GOIPA_TEST_PASSWD")
	_, err := c.Login(user, pass)
	if err != nil {
		t.Error(err)
	}

	// Test using ipa_session
	rec, err := c.UserShow(user)

	if err != nil {
		t.Error(err)
	}

	if string(rec.Uid) != user {
		t.Errorf("Invalid user")
	}

	if len(os.Getenv("GOIPA_TEST_KEYTAB")) > 0 {
		c.ClearSession()

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
	c := newClient()

	user := os.Getenv("GOIPA_TEST_USER")
	pass := os.Getenv("GOIPA_TEST_PASSWD")
	_, err := c.Login(user, pass)
	if err != nil {
		t.Error(err)
	}

	// Remove any existing public keys
	fp, err := c.UpdateSSHPubKeys(user, []string{})
	if err != nil {
		t.Error("Failed to remove existing ssh public keys")
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

	if fp[0] != "85:E6:E9:C1:7E:83:25:B9:1B:C0:B8:75:11:15:BD:83 test@localhost (ssh-rsa)" {
		t.Errorf("Invalid fingerprint")
	}
}

func TestAddTotpToken(t *testing.T) {
	c := newClient()

	user := os.Getenv("GOIPA_TEST_USER")
	pass := os.Getenv("GOIPA_TEST_PASSWD")
	_, err := c.Login(user, pass)
	if err != nil {
		t.Error(err)
	}

	err = c.RemoveOTPToken(user)
	if err != nil {
		if ierr, ok := err.(*IpaError); ok {
			// 4001 not found is OK anything else is not
			if ierr.Code != 4001 {
				t.Error(err)
			}
		} else {
			t.Error(err)
		}
	}

	uri, err := c.AddTOTPToken(user, AlgorithmSHA1, DigitsSix, 30)
	if err != nil {
		t.Error(err)
	}

	if len(uri) == 0 {
		t.Error("Invalid URI returned")
	}

	_, err = c.AddTOTPToken(user, AlgorithmSHA1, DigitsSix, 30)
	if err == nil {
		t.Error("Should not be able to set more than 1 OTP")
	}

	err = c.RemoveOTPToken(user)
	if err != nil {
		t.Error(err)
	}
}
