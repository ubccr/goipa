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
