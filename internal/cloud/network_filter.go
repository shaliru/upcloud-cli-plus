package cloud

import "github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"

// FilterNetworksByType returns networks for the given mode:
//   - "private": the user's SDN networks (Type == private)
//   - "all":     the input unchanged (includes UpCloud's public/utility infra)
//
// Any other mode yields an empty slice.
func FilterNetworksByType(items []upcloud.Network, mode string) []upcloud.Network {
	if mode == "all" {
		return items
	}
	if mode != "private" {
		return nil
	}
	var out []upcloud.Network
	for _, n := range items {
		if n.Type == upcloud.NetworkTypePrivate {
			out = append(out, n)
		}
	}
	return out
}
