package tui

import "github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"

type serversLoadedMsg struct{ servers []upcloud.Server }
type serverDetailMsg struct{ detail *upcloud.ServerDetails }
type ipsLoadedMsg struct{ ips []upcloud.IPAddress }
type actionDoneMsg struct{ action, ref string }
type errMsg struct{ err error }

type storageLoadedMsg struct{ items []upcloud.Storage }
type networksLoadedMsg struct{ items []upcloud.Network }
type storageDetailMsg struct{ detail *upcloud.StorageDetails }
