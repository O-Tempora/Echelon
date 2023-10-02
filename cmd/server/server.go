package main

import (
	"context"
	"fmt"
	"log"
	"strconv"

	netvuln "github.com/O-Tempora/Echelon/internal/api/netvuln_v1"
	"github.com/Ullaakut/nmap/v3"
	"golang.org/x/exp/slog"
)

type server struct {
	netvuln.UnimplementedNetVulnServiceServer
	logger *slog.Logger
}

func (s *server) CheckVuln(ctx context.Context, r *netvuln.CheckVulnRequest) (*netvuln.CheckVulnResponse, error) {
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithPorts(fmt.Sprintf("%d", r.GetTcpPort())),
		nmap.WithTargets(r.GetTargets()...),
		nmap.WithScripts("vulners"),
		nmap.WithScriptArguments(map[string]string{
			"mincvss": "0",
		}),
		nmap.WithAggressiveScan(),
	)
	if err != nil {
		return nil, err
	}

	s.logger.InfoContext(ctx, "Command executed",
		slog.Any("Args: ", scanner.Args()),
	)
	res, _, err := scanner.Run()
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to run nmap command", "Reason: ", err.Error())
		return nil, err
	}

	resp := &netvuln.CheckVulnResponse{
		Results: make([]*netvuln.TargetResult, 0),
	}
	for _, host := range res.Hosts {
		targetResult := &netvuln.TargetResult{
			Target: host.Addresses[0].Addr,
		}
		port := host.Ports[0]
		service := &netvuln.Service{
			TcpPort: int32(port.ID),
			Version: port.Service.Version,
			Name:    port.Service.Name,
			Vulns:   make([]*netvuln.Vulnerability, 0),
		}
		for _, scr := range port.Scripts {
			if scr.Tables != nil && len(scr.Tables) > 0 {
				for _, table := range scr.Tables {
					if table.Tables != nil && len(table.Tables) > 0 {
						for _, tb := range table.Tables {
							service.Vulns = append(service.Vulns, getVulnData(&tb))
						}
					}
				}
			}
		}
		targetResult.Services = service
		resp.Results = append(resp.Results, targetResult)
	}

	s.logger.InfoContext(ctx, "Successfull nmap call")
	return resp, nil
}

func getVulnData(table *nmap.Table) *netvuln.Vulnerability {
	if table == nil || len(table.Elements) == 0 {
		return nil
	}

	vuln := &netvuln.Vulnerability{}
	for _, e := range table.Elements {
		switch e.Key {
		case "id":
			vuln.Identifier = e.Value
		case "cvss":
			cvss, err := strconv.ParseFloat(e.Value, 32)
			if err != nil {
				log.Fatal(err.Error())
			}
			vuln.CvssScore = float32(cvss)
		default:
			continue
		}
	}
	return vuln
}
