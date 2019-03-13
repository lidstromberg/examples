package main

import (
	"log"
	"os"
	"strconv"
	"time"
)

//lbctxkey key type for use with context
type lbctxkey string

var (
	//EnvAuthUseGtway controls whether the request gateway is used
	EnvAuthUseGtway bool
	//EnvCtxTimeout is the general context timeout
	EnvCtxTimeout time.Duration
	//EnvDomain is the otp domain
	EnvDomain string
	//EnvPeriod is the otp lag period in seconds
	EnvPeriod int32
	//EnvRqAuthHdr is the canonical name for the authorization header
	EnvRqAuthHdr string
	//EnvCtxKey general authorization key
	EnvCtxKey lbctxkey
)

//preflight loads the config
func preflight() {
	//get the gateway flag
	usewl, err := strconv.ParseBool(os.Getenv("SVCAUTH_USE_GTWAY"))

	if err != nil {
		log.Fatal("Could not parse environment variable EnvAuthUseGtway")
	}

	EnvAuthUseGtway = usewl

	//set the context timeout
	to, err := time.ParseDuration(os.Getenv("SVCAUTH_CTX_TO"))

	if err != nil {
		log.Fatal("Could not parse environment variable EnvCtxTimeout")
	}

	EnvCtxTimeout = to

	//set the domain (should match the JWT issuer)
	EnvDomain = os.Getenv("JWT_ISSUER")

	if EnvDomain == "" {
		log.Fatal("Could not parse environment variable EnvDomain")
	}

	//set the otp period
	pd, err := strconv.ParseInt(os.Getenv("SVCAUTH_OTP_PD"), 10, 64)

	if err != nil {
		log.Fatal("Could not parse environment variable EnvPeriod")
	}

	EnvPeriod = int32(pd)

	//Get the request header label
	EnvRqAuthHdr = os.Getenv("SVCAUTH_AUTH_HD")

	if EnvRqAuthHdr == "" {
		log.Fatal("Could not parse environment variable EnvRqAuthHdr")
	}

	//set the context authorization key
	EnvCtxKey = lbctxkey(EnvRqAuthHdr)
}
