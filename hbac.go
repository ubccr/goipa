package ipa

// создать ноове правило hbac
func (c *Client) HbacRuleAdd(name string) error {
	_, err := c.rpc("hbacrule_add", []string{name}, map[string]interface{}{})
	return err
}

func (c *Client) HbacRuleDelete(name string) error {
	_, err := c.rpc("hbacrule_del", []string{name}, map[string]interface{}{})
	return err
}

// добавить группы в правило hbac
func (c *Client) HbacRuleAddUser(hbacName string, groupName ...string) error {
	var options = map[string]interface{}{
		"all":   true,
		"group": groupName,
	}
	_, err := c.rpc("hbacrule_add_user", []string{hbacName}, options)
	return err
}

// добавить пользователей в правило hbac
func (c *Client) HbacRuleRemoveUser(hbacName string, groupName ...string) error {
	var options = map[string]interface{}{
		"all":   true,
		"group": groupName,
	}
	_, err := c.rpc("hbacrule_remove_user", []string{hbacName}, options)
	return err
}
