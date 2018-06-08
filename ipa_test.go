// Copyright 2018 Andrew E. Bruno. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package ipa

import (
	"fmt"
	"os"
	"testing"
)

func newTestClientUserPassword() *Client {
	host := os.Getenv("GOIPA_TEST_HOST")
	username := os.Getenv("GOIPA_TEST_USER")
	password := os.Getenv("GOIPA_TEST_PASSWORD")
	realm := os.Getenv("GOIPA_TEST_REALM")

	c := NewClient(host, realm)

	err := c.Login(username, password)
	if err != nil {
		panic(err)
	}

	return c
}

func newTestClientKeytab() *Client {
	host := os.Getenv("GOIPA_TEST_HOST")
	keytab := os.Getenv("GOIPA_TEST_KEYTAB")
	username := os.Getenv("GOIPA_TEST_KTUSER")
	realm := os.Getenv("GOIPA_TEST_REALM")

	c := NewClient(host, realm)

	err := c.LoginWithKeytab(keytab, username)
	if err != nil {
		panic(err)
	}

	return c
}

func TestPing(t *testing.T) {
	user := os.Getenv("GOIPA_TEST_USER")
	realm := os.Getenv("GOIPA_TEST_REALM")

	c := newTestClientUserPassword()

	res, err := c.Ping()
	if err != nil {
		t.Fatal(err)
	}

	princ := fmt.Sprintf("%s@%s", user, realm)
	if princ != res.Principal {
		t.Errorf("Wrong principal: got %s expected %s", res.Principal, princ)
	}

	if len(c.SessionID()) == 0 {
		t.Errorf("SessionID not set")
	}
}
