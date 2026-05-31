// Package cloud is the shared core: a thin, mockable interface over the
// UpCloud Go SDK that both the CLI and the TUI depend on.
package cloud

import (
	"context"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud/request"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud/service"
)

// Service is the domain API used by every front-end. Returning SDK types keeps
// the adapter thin; the interface boundary is where tests inject a Fake.
type Service interface {
	ListServers(ctx context.Context) ([]upcloud.Server, error)
	GetServer(ctx context.Context, uuid string) (*upcloud.ServerDetails, error)
	ListIPAddresses(ctx context.Context) ([]upcloud.IPAddress, error)
	StartServer(ctx context.Context, uuid string) error
	StopServer(ctx context.Context, uuid string) error
	RestartServer(ctx context.Context, uuid string) error
}

type sdkService struct {
	svc *service.Service
}

// New wraps an SDK service in the Service interface.
func New(svc *service.Service) Service {
	return &sdkService{svc: svc}
}

func (s *sdkService) ListServers(ctx context.Context) ([]upcloud.Server, error) {
	res, err := s.svc.GetServers(ctx)
	if err != nil {
		return nil, err
	}
	return res.Servers, nil
}

func (s *sdkService) GetServer(ctx context.Context, uuid string) (*upcloud.ServerDetails, error) {
	return s.svc.GetServerDetails(ctx, &request.GetServerDetailsRequest{UUID: uuid})
}

func (s *sdkService) ListIPAddresses(ctx context.Context) ([]upcloud.IPAddress, error) {
	res, err := s.svc.GetIPAddresses(ctx)
	if err != nil {
		return nil, err
	}
	return res.IPAddresses, nil
}

func (s *sdkService) StartServer(ctx context.Context, uuid string) error {
	_, err := s.svc.StartServer(ctx, &request.StartServerRequest{UUID: uuid})
	return err
}

func (s *sdkService) StopServer(ctx context.Context, uuid string) error {
	_, err := s.svc.StopServer(ctx, &request.StopServerRequest{
		UUID:     uuid,
		StopType: request.ServerStopTypeSoft,
	})
	return err
}

func (s *sdkService) RestartServer(ctx context.Context, uuid string) error {
	_, err := s.svc.RestartServer(ctx, &request.RestartServerRequest{
		UUID:     uuid,
		StopType: request.ServerStopTypeSoft,
	})
	return err
}
