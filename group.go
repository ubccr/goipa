// Copyright 2021 Ivan Ermilov. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

// Package ipa is a Go client library for FreeIPA
package ipa

import (
	"encoding/json"
	"errors"
	"fmt"
)

type GroupRecord struct {
	Dn          string   `json:"dn"`
	Cn          []string `json:"cn"`
	IpaUniqueId []string `json:"ipauniqueid"`
	GidNumber   []string `json:"gidnumber"`
	ObjectClass []string `json:"objectclass"`
	Users       []string `json:"member_user"`
}

var ErrorGroupRecordNotInitialized = errors.New("group record is not initialized")

func (g *GroupRecord) getCn() (string, error) {
	var cn string
	if len(g.Cn) <= 0 {
		return cn, ErrorGroupRecordNotInitialized
	}
	return g.Cn[0], nil
}

func (c *Client) GroupAdd(cn string) (*GroupRecord, error) {
	var groupRec *GroupRecord

	var options = map[string]interface{}{}

	res, err := c.rpc("group_add", []string{cn}, options)
	if err != nil {
		return groupRec, err
	}

	err = json.Unmarshal(res.Result.Data, &groupRec)
	if err != nil {
		return groupRec, err
	}

	return groupRec, nil
}

func (c *Client) GroupDelete(cn string) error {
	var options = map[string]interface{}{}

	_, err := c.rpc("group_del", []string{cn}, options)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) GroupShow(cn string) (*GroupRecord, error) {
	var groupRec *GroupRecord

	var options = map[string]interface{}{
		"no_members": false,
		"raw":        false,
		"all":        false,
		"rights":     false,
	}

	res, err := c.rpc("group_show", []string{cn}, options)
	if err != nil {
		return groupRec, err
	}

	err = json.Unmarshal(res.Result.Data, &groupRec)
	if err != nil {
		return groupRec, err
	}

	return groupRec, nil
}

func (c *Client) AddUserToGroup(groupCn string, userUid string) (*GroupRecord, error) {
	var groupRec *GroupRecord

	var options = map[string]interface{}{
		"no_members": false,
		"raw":        false,
		"all":        false,
		"user":       []string{userUid},
	}

	res, err := c.rpc("group_add_member", []string{groupCn}, options)
	if err != nil {
		return groupRec, err
	}

	fmt.Printf("%s\n", res.Result.Data)

	err = json.Unmarshal(res.Result.Data, &groupRec)
	if err != nil {
		return groupRec, err
	}

	return groupRec, nil
}

func (c *Client) RemoveUserFromGroup(groupCn string, userUid string) error {
	var options = map[string]interface{}{
		"no_members": false,
		"raw":        false,
		"all":        false,
		"user":       []string{userUid},
	}

	_, err := c.rpc("group_remove_member", []string{groupCn}, options)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) CheckUserMemberOfGroup(userName, groupName string) (bool, error) {
	group, err := c.GroupShow(groupName)
	if err != nil {
		return false, err
	}

	for _, u := range group.Users {
		if u == userName {
			return true, nil
		}
	}

	return false, nil
}
