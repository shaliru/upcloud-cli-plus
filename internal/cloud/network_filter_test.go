package cloud

import (
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
)

func sampleNetworks() []upcloud.Network {
	return []upcloud.Network{
		{UUID: "p1", Name: "my-sdn", Type: upcloud.NetworkTypePrivate},
		{UUID: "pub1", Name: "Public sg-sin1", Type: upcloud.NetworkTypePublic},
		{UUID: "ut1", Name: "Utility sg-sin1", Type: upcloud.NetworkTypeUtility},
	}
}

func netUUIDs(items []upcloud.Network) []string {
	out := make([]string, len(items))
	for i, n := range items {
		out[i] = n.UUID
	}
	return out
}

func TestFilterNetworksByType(t *testing.T) {
	n := sampleNetworks()
	assert.Equal(t, []string{"p1"}, netUUIDs(FilterNetworksByType(n, "private")))
	assert.Equal(t, []string{"p1", "pub1", "ut1"}, netUUIDs(FilterNetworksByType(n, "all")), "all is unfiltered")
	assert.Empty(t, FilterNetworksByType(n, "bogus"), "unknown mode yields nothing")
}
