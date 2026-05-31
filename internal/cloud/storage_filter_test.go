package cloud

import (
	"testing"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/stretchr/testify/assert"
)

func sampleStorages() []upcloud.Storage {
	return []upcloud.Storage{
		{UUID: "d1", Title: "disk-a", Type: upcloud.StorageTypeNormal, Access: upcloud.StorageAccessPrivate},
		{UUID: "b1", Title: "backup-a", Type: upcloud.StorageTypeBackup, Access: upcloud.StorageAccessPrivate},
		{UUID: "c1", Title: "myimage", Type: upcloud.StorageTypeTemplate, Access: upcloud.StorageAccessPrivate},
		{UUID: "t1", Title: "Ubuntu 24.04", Type: upcloud.StorageTypeTemplate, Access: upcloud.StorageAccessPublic},
		{UUID: "cd1", Title: "some.iso", Type: upcloud.StorageTypeCDROM, Access: upcloud.StorageAccessPublic},
	}
}

func uuids(items []upcloud.Storage) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = s.UUID
	}
	return out
}

func TestFilterStorageByCategory(t *testing.T) {
	s := sampleStorages()
	assert.Equal(t, []string{"d1"}, uuids(FilterStorageByCategory(s, "devices")))
	assert.Equal(t, []string{"b1"}, uuids(FilterStorageByCategory(s, "backups")))
	assert.Equal(t, []string{"c1"}, uuids(FilterStorageByCategory(s, "images")), "public templates and cdrom excluded")
	assert.Equal(t, []string{"d1", "b1", "c1", "t1", "cd1"}, uuids(FilterStorageByCategory(s, "all")), "all is unfiltered")
	assert.Empty(t, FilterStorageByCategory(s, "bogus"), "unknown category yields nothing")
}
