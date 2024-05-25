package ipa

// создать ноове правило hbac
func (c *Client) Passwd(userName, newPassword string) error {
	var options = map[string]interface{}{
		"password": newPassword,
	}

	_, err := c.rpc("passwd", []string{userName}, options)
	return err
}
