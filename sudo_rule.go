package ipa

// Добавить пользователей и группы, которых касается правило Sudo.
func (c *Client) SudoRuleAddUser(ruleName, groupName string) error {
	var options = map[string]interface{}{
		"group": groupName,
	}

	_, err := c.rpc("sudorule_add_user", []string{ruleName}, options)
	return err
}
