package cloud

import (
	"context"
	"fmt"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
)

// Fake is an in-memory Service for tests. Set Err to force errors.
type Fake struct {
	Servers []upcloud.Server
	Details map[string]*upcloud.ServerDetails
	IPs     []upcloud.IPAddress
	Err     error

	Started   []string
	Stopped   []string
	Restarted []string
}

func (f *Fake) ListServers(ctx context.Context) ([]upcloud.Server, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Servers, nil
}

func (f *Fake) GetServer(ctx context.Context, uuid string) (*upcloud.ServerDetails, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	d, ok := f.Details[uuid]
	if !ok {
		return nil, fmt.Errorf("server %q not found", uuid)
	}
	return d, nil
}

func (f *Fake) ListIPAddresses(ctx context.Context) ([]upcloud.IPAddress, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.IPs, nil
}

func (f *Fake) StartServer(ctx context.Context, uuid string) error {
	if f.Err != nil {
		return f.Err
	}
	f.Started = append(f.Started, uuid)
	return nil
}

func (f *Fake) StopServer(ctx context.Context, uuid string) error {
	if f.Err != nil {
		return f.Err
	}
	f.Stopped = append(f.Stopped, uuid)
	return nil
}

func (f *Fake) RestartServer(ctx context.Context, uuid string) error {
	if f.Err != nil {
		return f.Err
	}
	f.Restarted = append(f.Restarted, uuid)
	return nil
}
