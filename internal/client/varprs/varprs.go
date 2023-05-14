package varprs

import "flag"

// CertCrtPath - Path to crt file for TLS
var CertCrtPath string

// ServerAddress - address for running GophKeeper server
var ServerAddress string

func Init() {
	flag.StringVar(&CertCrtPath, "crt", "/home/glebov-da/GoStudying/repo/GophKeeperDiploma/cmd/localhost.crt", "Path to crt file for TLS")
	flag.StringVar(&ServerAddress, "a", "localhost:8400", "Server address")
	flag.Parse()
}
