package tui

import (
	"strings"
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
)

func TestRenderServerDetail(t *testing.T) {
	d := &upcloud.ServerDetails{
		Server: upcloud.Server{
			UUID: "u1", Hostname: "web-sg-1", Title: "web-sg-1",
			Plan: "1xCPU-2GB", Zone: "sg-sin1", State: "started",
		},
		ServerGroup: "dev-md",
		Timezone:    "UTC",
	}
	out := renderServerDetail(d, 60)
	assert.Contains(t, out, "web-sg-1")
	assert.Contains(t, out, "1xCPU-2GB")
	assert.Contains(t, out, "sg-sin1")
	assert.Contains(t, out, "started")
	assert.True(t, strings.Contains(out, "Overview"))
}

func TestRenderServerDetail_Nil(t *testing.T) {
	assert.Equal(t, "", renderServerDetail(nil, 60))
}
