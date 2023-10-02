package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	service "github.com/O-Tempora/Echelon/internal/api/netvuln_v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gopkg.in/yaml.v3"
)

var (
	serviceConfig string
)

type config struct {
	Port     int    `yaml:"port"`
	LogLevel string `yaml:"loglevel"`
	LogPath  string `yaml:"logpath"`
}

func init() {
	flag.StringVar(&serviceConfig, "config", "config/default.yaml", "path to config file")
}

func main() {
	//Parsing flags and retreiving config
	flag.Parse()
	cf, err := getConfig(serviceConfig)
	if err != nil {
		log.Fatal(err.Error())
	}

	//Creating new gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cf.Port))
	if err != nil {
		log.Fatal(err.Error())
	}
	s := grpc.NewServer()
	reflection.Register(s)

	//Seting up logger
	lev := new(slog.LevelVar)
	setLogLevel(lev, cf.LogLevel)
	serv := &server{
		logger: slog.New(slog.NewJSONHandler(getLogOutput(cf.LogPath), &slog.HandlerOptions{
			Level: lev,
		})),
	}

	//Starting server
	service.RegisterNetVulnServiceServer(s, serv)

	serv.logger.Info("Server started: ",
		slog.Int("port", cf.Port),
		slog.String("log level", cf.LogLevel),
	)
	if err = s.Serve(lis); err != nil {
		log.Fatal(err.Error())
	}
}

func getConfig(path string) (*config, error) {
	configBytes, err := os.ReadFile(serviceConfig)
	if err != nil {
		return nil, err
	}

	cf := &config{}
	if err = yaml.Unmarshal(configBytes, cf); err != nil {
		return nil, err
	}
	return cf, nil
}
func getLogOutput(path string) io.Writer {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return os.Stdout
	}
	return io.MultiWriter(os.Stdout, file)
}
func setLogLevel(lev *slog.LevelVar, cfLevel string) {
	switch cfLevel {
	case "INFO":
		lev.Set(slog.LevelInfo)
	case "DEBUG":
		lev.Set(slog.LevelDebug)
	case "WARN":
		lev.Set(slog.LevelWarn)
	case "ERROR":
		lev.Set(slog.LevelError)
	default:
		lev.Set(slog.LevelInfo)
	}
}
