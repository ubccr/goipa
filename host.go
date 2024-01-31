package ipa

func (c *Client) HostAdd(fqdn string, force bool, ipAddress string) error {
	var options = map[string]interface{}{
		"force":      force,
		"ip_address": ipAddress,
	}

	_, err := c.rpc("host_add", []string{fqdn}, options)
	if err != nil {
		return err
	}

	return nil
}

// todo тонкое место не совсем понятно как работает
func (c *Client) HostExists(name string) (bool, error) {
	var options = map[string]interface{}{}

	res, err := c.rpc("host_find", []string{name}, options)
	if err != nil {
		return false, err
	}

	bytes, err := res.Result.Data.MarshalJSON()
	if err != nil {
		return false, err
	}

	if len(bytes) < 3 {
		return false, nil
	}

	return true, nil
}

func (c *Client) HostDel(fqdn string) error {
	var options = map[string]interface{}{}

	_, err := c.rpc("host_del", []string{fqdn}, options)
	if err != nil {
		return err
	}

	return nil
}
