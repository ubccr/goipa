package ipa

import "encoding/json"

func (c *Client) HostGroupAdd(cn string) (*GroupRecord, error) {
	var groupRec *GroupRecord

	var options = map[string]interface{}{}

	res, err := c.rpc("hostgroup_add", []string{cn}, options)
	if err != nil {
		return groupRec, err
	}

	err = json.Unmarshal(res.Result.Data, &groupRec)
	if err != nil {
		return groupRec, err
	}

	return groupRec, nil
}

//HostGroupAddMember добавляет сервер к группе узлов (под member тут имеется в виду сервер, пример :"ttt-ttt-tst08.tst.cloud.vimpelcom.ru")
func (c *Client) HostGroupAddMember(groupCn string, host string) (*GroupRecord, error) {
	var groupRec *GroupRecord

	var options = map[string]interface{}{
		"all":  true,
		"host": []string{host},
	}

	res, err := c.rpc("hostgroup_add_member", []string{groupCn}, options)
	if err != nil {
		return groupRec, err
	}

	err = json.Unmarshal(res.Result.Data, &groupRec)
	if err != nil {
		return groupRec, err
	}

	return groupRec, nil
}

//HostGroupRemoveMember удаляет сервер из группы узлов (под member тут имеется в виду сервер, пример :"ttt-ttt-tst08.tst.cloud.vimpelcom.ru")
func (c *Client) HostGroupRemoveMember(groupCn string, host string) error {
	var options = map[string]interface{}{
		"all":  true,
		"host": []string{host},
	}

	_, err := c.rpc("hostgroup_remove_member", []string{groupCn}, options)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) HostGroupDelete(cn string) error {
	var options = map[string]interface{}{}

	_, err := c.rpc("hostgroup_del", []string{cn}, options)
	if err != nil {
		return err
	}

	return nil
}
