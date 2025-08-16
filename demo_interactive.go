package main

import (
	"context"
	"fmt"
	"os"

	"github.com/UpCloudLtd/upcloud-cli/v3/internal/commands/server"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/mock"
	"github.com/UpCloudLtd/upcloud-cli/v3/internal/mockexecute"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
)

func main() {
	// Create mock server data
	mockServers := &upcloud.Servers{
		Servers: []upcloud.Server{
			{
				UUID:     "00000000-0000-0000-0000-000000000001",
				Hostname: "web-server-01",
				Plan:     "1xCPU-1GB",
				Zone:     "nl-ams1",
				State:    "started",
				Tags:     []string{"web", "production"},
			},
			{
				UUID:     "00000000-0000-0000-0000-000000000002",
				Hostname: "db-server-01",
				Plan:     "2xCPU-4GB",
				Zone:     "us-nyc1",
				State:    "stopped",
				Tags:     []string{"database", "mysql"},
			},
			{
				UUID:     "00000000-0000-0000-0000-000000000003",
				Hostname: "api-server-01",
				Plan:     "1xCPU-2GB",
				Zone:     "uk-lon1",
				State:    "started",
				Tags:     []string{"api", "production"},
			},
			{
				UUID:     "00000000-0000-0000-0000-000000000004",
				Hostname: "test-server-01",
				Plan:     "1xCPU-1GB",
				Zone:     "fi-hel1",
				State:    "maintenance",
				Tags:     []string{"testing"},
			},
		},
	}

	// Create mock service
	mockService := &mock.Service{}
	mockService.On("GetServers").Return(mockServers, nil)

	// Create mock executor
	exec := &mockexecute.MockExecutor{}
	exec.On("All").Return(mockService)
	exec.On("Context").Return(context.Background())

	// Create the list command with interactive flag set
	listCmd := server.ListCommand().(*server.ListCommand)
	listCmd.Interactive = true

	fmt.Println("🚀 Demo: Interactive Server Selection")
	fmt.Println("=====================================")
	fmt.Println("This demonstrates the new interactive server selection feature!")
	fmt.Println("Use arrow keys to navigate, type to search, and press Enter to select.")
	fmt.Println("")

	// Execute the interactive command
	output, err := listCmd.ExecuteWithoutArguments(exec)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Result: %+v\n", output)
}
