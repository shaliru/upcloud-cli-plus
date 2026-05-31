package cloud

import "github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"

// FilterStorageByCategory returns the storages in the given category:
//   - "devices": real block-storage disks (Type normal)
//   - "backups": storage backups (Type backup)
//   - "images":  the user's own templates (Type template, private access)
//   - "all":     the input unchanged (raw, including public templates and cdroms)
//
// Public templates (template + public) and cdroms are excluded from the named
// categories. An unknown category yields an empty slice.
func FilterStorageByCategory(items []upcloud.Storage, category string) []upcloud.Storage {
	if category == "all" {
		return items
	}
	var out []upcloud.Storage
	for _, s := range items {
		if storageInCategory(s, category) {
			out = append(out, s)
		}
	}
	return out
}

func storageInCategory(s upcloud.Storage, category string) bool {
	switch category {
	case "devices":
		return s.Type == upcloud.StorageTypeNormal
	case "backups":
		return s.Type == upcloud.StorageTypeBackup
	case "images":
		return s.Type == upcloud.StorageTypeTemplate && s.Access == upcloud.StorageAccessPrivate
	default:
		return false
	}
}
