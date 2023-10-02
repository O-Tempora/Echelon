package main

import (
	"context"
	"log"
	"net"
	"os"
	"testing"

	netvuln "github.com/O-Tempora/Echelon/internal/api/netvuln_v1"
	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func createTestingEnv(ctx context.Context) (netvuln.NetVulnServiceClient, func()) {
	buffer := 101024 * 1024
	lis := bufconn.Listen(buffer)
	baseServer := grpc.NewServer()

	netvuln.RegisterNetVulnServiceServer(baseServer, &server{
		logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	})
	go func() {
		if err := baseServer.Serve(lis); err != nil {
			log.Fatalf("error serving server: %v", err)
		}
	}()

	conn, err := grpc.DialContext(ctx, "",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("error connecting to server: %v", err)
	}

	closer := func() {
		err := lis.Close()
		if err != nil {
			log.Fatalf("error closing listener: %v", err)
		}
		baseServer.Stop()
	}

	client := netvuln.NewNetVulnServiceClient(conn)
	return client, closer
}

func TestServer_CheckVuln(t *testing.T) {
	ctx := context.Background()
	client, closer := createTestingEnv(ctx)
	defer closer()

	type expected struct {
		response *netvuln.CheckVulnResponse
		err      error
	}
	tests := map[string]struct {
		in          *netvuln.CheckVulnRequest
		expectation *expected
	}{
		"Wrong Host": {
			in: &netvuln.CheckVulnRequest{
				TcpPort: 80,
				Targets: []string{"aintnoway it works"},
			},
			expectation: &expected{
				response: nil,
				err:      status.Error(codes.InvalidArgument, "No such hosts"),
			},
		},
		"Wrong Port": {
			in: &netvuln.CheckVulnRequest{
				TcpPort: 99999999,
				Targets: []string{"scanme.nmap.org"},
			},
			expectation: &expected{
				response: nil,
				err:      status.Error(codes.Unknown, "exit status 1"),
			},
		},
		"Wrong Both": {
			in: &netvuln.CheckVulnRequest{
				TcpPort: 99956789,
				Targets: []string{"qhfwqof.org"},
			},
			expectation: &expected{
				response: nil,
				err:      status.Error(codes.Unknown, "exit status 1"),
			},
		},
		"Closed Port": {
			in: &netvuln.CheckVulnRequest{
				TcpPort: 443,
				Targets: []string{"scanme.nmap.org"},
			},
			expectation: &expected{
				response: &netvuln.CheckVulnResponse{
					Results: []*netvuln.TargetResult{
						{
							Target: "45.33.32.156",
							Services: &netvuln.Service{
								Vulns:   []*netvuln.Vulnerability{},
								Name:    "https",
								Version: "",
								TcpPort: 443,
							},
						},
					},
				},
				err: nil,
			},
		},
	}

	for scenario, table := range tests {
		t.Run(scenario, func(t *testing.T) {
			resp, err := client.CheckVuln(ctx, table.in)
			if err != nil {
				if table.expectation.err.Error() != err.Error() {
					t.Errorf("Err -> \nExpected: %q\nGot: %q\n", table.expectation.err, err)
				}
			} else {
				if table.expectation.response.Results == nil ||
					resp.Results == nil ||
					!slices.Equal[[]*netvuln.TargetResult, *netvuln.TargetResult](table.expectation.response.Results, resp.Results) {
					t.Errorf("Results -> \nExpected: %v\nGot: %v\n", table.expectation.response.Results, resp.Results)
				}
			}
		})
	}
}
