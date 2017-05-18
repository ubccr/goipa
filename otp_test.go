// Copyright 2015 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"os"
	"testing"
)

func TestAddTOTPToken(t *testing.T) {
	c := newClient()

	user := os.Getenv("GOIPA_TEST_USER")
	pass := os.Getenv("GOIPA_TEST_PASSWD")
	_, err := c.Login(user, pass)
	if err != nil {
		t.Error(err)
	}

	err = c.RemoveOTPToken("token_does_not_exist")
	if err == nil {
		t.Error(err)
	}

	token, err := c.AddTOTPToken(user, "", AlgorithmSHA1, DigitsSix, 30, true)
	if err != nil {
		t.Error(err)
	}

	if len(token.URI) == 0 {
		t.Error("Invalid URI returned")
	}

	if token.Algorithm != AlgorithmSHA1 {
		t.Error("Invalid algorithm returned")
	}

	if token.Digits != DigitsSix {
		t.Error("Invalid digits returned")
	}

	if token.Enabled() == true {
		t.Error("Token should be disabled")
	}

	tokens, err := c.FetchOTPTokens(user)
	if err != nil {
		t.Error(err)
	}

	found := false
	for _, x := range tokens {
		if x.UUID == token.UUID {
			found = true
		}
	}

	if !found {
		t.Error("New Token not found")
	}

	err = c.EnableOTPToken(string(token.UUID))
	if err != nil {
		t.Error(err)
	}

	tokens, err = c.FetchOTPTokens(user)
	if err != nil {
		t.Error(err)
	}

	found = false
	for _, x := range tokens {
		if x.UUID == token.UUID && x.Enabled() {
			found = true
		}
	}

	if !found {
		t.Error("Token should now be enabled but was not found")
	}

	err = c.RemoveOTPToken(string(token.UUID))
	if err != nil {
		t.Error(err)
	}

	tokens, err = c.FetchOTPTokens(user)
	if err != nil {
		t.Error(err)
	}

	for _, x := range tokens {
		if x.UUID == token.UUID {
			t.Error("Deleted token still exists")
		}
	}
}
