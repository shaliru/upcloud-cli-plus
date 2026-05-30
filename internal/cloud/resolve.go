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
