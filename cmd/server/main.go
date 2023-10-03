package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	netvuln "github.com/O-Tempora/Echelon/internal/api/netvuln_v1"
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

	//Setting up logger
	level := new(slog.LevelVar)
	setLogLevel(level, cf.LogLevel)
	serv := &server{
		logger: slog.New(slog.NewJSONHandler(getLogOutput(cf.LogPath), &slog.HandlerOptions{
			Level: level,
		})),
	}

	//Starting server
	netvuln.RegisterNetVulnServiceServer(s, serv)

	serv.logger.Info("Server started: ",
		slog.Int("port", cf.Port),
		slog.String("log level", cf.LogLevel),
	)
	if err = s.Serve(lis); err != nil {
		log.Fatal(err.Error())
	}
}

// Get and unmarshall config from yaml file
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

// Get log output (stdout or stdout + file)
func getLogOutput(path string) io.Writer {
	if err := os.MkdirAll("logs", os.ModePerm); err != nil {
		return os.Stdout
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return os.Stdout
	}
	return io.MultiWriter(os.Stdout, file)
}

// Set logger log level from config
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
