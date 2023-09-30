package main

import (
	"context"
	"errors"

	service "github.com/O-Tempora/Echelon/internal/api/netvuln_v1"
)

func (s *server) CheckVuln(context.Context, *service.CheckVulnRequest) (*service.CheckVulnResponse, error) {
	return nil, errors.ErrUnsupported
}
