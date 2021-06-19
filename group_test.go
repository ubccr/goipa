package ipa

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/go-uuid"
)

func setUp(users []string, c *Client) {
	for _, u := range users {
		c.UserAdd(
			u,
			"test1@example.com",
			"firstname",
			"lastname",
			"/home/test1",
			"/bin/bash",
			false,
		)
	}
}

func tearDown(users []string, c *Client) {
	for _, u := range users {
		err := c.UserDelete(u)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func TestGroup(t *testing.T) {
	host := os.Getenv("GOIPA_TEST_HOST")
	realm := os.Getenv("GOIPA_TEST_REALM")
	c := NewClient(host, realm)
	user := os.Getenv("GOIPA_TEST_USER")
	pass := os.Getenv("GOIPA_TEST_PASSWD")
	err := c.RemoteLogin(user, pass)
	if err != nil {
		t.Error(err)
	}

	var users []string
	numUsers := 5
	// userPrefix should be lowercase, freeipa will make all ids lowercase
	userPrefix := "testuser"
	for i := 1; i <= numUsers; i++ {
		user := userPrefix + strconv.Itoa(i*10000+1)
		users = append(users, user)
	}
	setUp(users, c)
	t.Log("Added users to freeipa", users)

	groupName, err := uuid.GenerateUUID()
	if err != nil {
		t.Error(err)
	}

	t.Logf("Given group with a generated name: %s\n", groupName)

	res, err := c.GroupAdd(groupName)
	if err != nil {
		t.Logf("Could not add new group %s to freeipa\n", groupName)
		t.Error(err)
	}
	t.Logf("Added new group to freeipa: %+v\n", res)

	group, err := c.GroupShow(groupName)
	if err != nil {
		t.Logf("Not able to to fetch group %s from freeipa server", groupName)
		t.Error(err)
	}
	t.Logf("Was able to fetch group %s from freeipa server", groupName)
	t.Logf("%+v\n", group)

	for _, u := range users {
		groupWithMembers, err := c.AddUserToGroup(groupName, u)
		if err != nil {
			t.Logf("Could not add user %s to group %s\n", u, groupName)
			t.Error(err)
		}
		isMember, err := c.CheckUserMemberOfGroup(u, groupName)
		if err != nil {
			t.Error(err)
		}
		if !isMember {
			t.Errorf("User %s was not added to group %s", u, groupName)
		}
		t.Logf("%+v\n", groupWithMembers)
		t.Logf("Added user %s to group %s\n", u, groupName)
	}

	userToRemove := users[0]
	err = c.RemoveUserFromGroup(groupName, userToRemove)
	if err != nil {
		t.Logf("Could not remove user %s from group %s", userToRemove, groupName)
		t.Error(err)
	}
	t.Logf("Removed User %s from group %s", userToRemove, groupName)
	isMember, _ := c.CheckUserMemberOfGroup(userToRemove, groupName)
	if isMember {
		t.Errorf("User %s was not removed from group %s", userToRemove, groupName)
	}
	t.Logf("Checked that user %s was removed from group %s", userToRemove, groupName)

	err = c.GroupDelete(groupName)
	if err != nil {
		t.Logf("Could not delete group %s\n", groupName)
		t.Error(err)
	}
	t.Logf("Deleted group %s from freeipa\n", groupName)

	tearDown(users, c)
	t.Log("Deleted users from freeipa", users)
}
