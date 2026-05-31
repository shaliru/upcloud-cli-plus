package cloud

import (
	"context"
	"fmt"
)

// ResolveServer maps a reference (UUID, hostname, or title) to a server UUID.
// An exact UUID match wins immediately. Otherwise hostname then title are
// matched; multiple matches return an "ambiguous" error.
func ResolveServer(ctx context.Context, svc Service, ref string) (string, error) {
	servers, err := svc.ListServers(ctx)
	if err != nil {
		return "", err
	}

	for _, s := range servers {
		if s.UUID == ref {
			return s.UUID, nil
		}
	}

	var matches []string
	for _, s := range servers {
		if s.Hostname == ref || s.Title == ref {
			matches = append(matches, s.UUID)
		}
	}

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no server matches %q", ref)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous reference %q matches %d servers; use the UUID", ref, len(matches))
	}
}

// ResolveStorage maps a reference (UUID or title) to a storage UUID.
func ResolveStorage(ctx context.Context, svc Service, ref string) (string, error) {
	storages, err := svc.ListStorage(ctx)
	if err != nil {
		return "", err
	}
	for _, s := range storages {
		if s.UUID == ref {
			return s.UUID, nil
		}
	}
	var matches []string
	for _, s := range storages {
		if s.Title == ref {
			matches = append(matches, s.UUID)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no storage matches %q", ref)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous reference %q matches %d storages; use the UUID", ref, len(matches))
	}
}

// ResolveNetwork maps a reference (UUID or name) to a network UUID.
func ResolveNetwork(ctx context.Context, svc Service, ref string) (string, error) {
	networks, err := svc.ListNetworks(ctx)
	if err != nil {
		return "", err
	}
	for _, n := range networks {
		if n.UUID == ref {
			return n.UUID, nil
		}
	}
	var matches []string
	for _, n := range networks {
		if n.Name == ref {
			matches = append(matches, n.UUID)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no network matches %q", ref)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous reference %q matches %d networks; use the UUID", ref, len(matches))
	}
}
