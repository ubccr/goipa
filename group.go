package ipa

import "context"

// https://freeipa.readthedocs.io/en/latest/api/group_add_member.html
// https://github.com/freeipa/freeipa/blob/c40ce0e1ff01cbecf2d83377f48c0ace55fd1ed9/ipaserver/plugins/group.py#L633
func (c *Client) GroupAddMember(ctx context.Context, gid string, memberId string, memberType string) (*Response, error) {
	options := map[string]any{}

	switch memberType {
	case "user":
		options["user"] = memberId
	case "group":
		options["group"] = memberId
	case "service":
		options["service"] = memberId
	}

	res, err := c.rpcContext(ctx, "group_add_member", []string{gid}, options)
	if err != nil {
		return nil, err
	}

	return res, nil
}
