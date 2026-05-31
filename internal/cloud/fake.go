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

	Storages       []upcloud.Storage
	StorageDetails map[string]*upcloud.StorageDetails
	Networks       []upcloud.Network
	NetworkDetails map[string]*upcloud.Network
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

func (f *Fake) ListStorage(ctx context.Context) ([]upcloud.Storage, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Storages, nil
}

func (f *Fake) GetStorage(ctx context.Context, uuid string) (*upcloud.StorageDetails, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	d, ok := f.StorageDetails[uuid]
	if !ok {
		return nil, fmt.Errorf("storage %q not found", uuid)
	}
	return d, nil
}

func (f *Fake) ListNetworks(ctx context.Context) ([]upcloud.Network, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Networks, nil
}

func (f *Fake) GetNetwork(ctx context.Context, uuid string) (*upcloud.Network, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	d, ok := f.NetworkDetails[uuid]
	if !ok {
		return nil, fmt.Errorf("network %q not found", uuid)
	}
	return d, nil
}
