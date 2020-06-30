// Copyright 2020 The Cockroach Authors.
//
// Licensed as a CockroachDB Enterprise file under the Cockroach Community
// License (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     https://github.com/cockroachdb/cockroach/blob/master/licenses/CCL.txt

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	proxy "github.com/cockroachdb/cockroach/pkg/sql/sqlproxy"
)

var options struct {
	listenAddress string
	targetAddress string
	cert          string
	key           string
	verify        bool

	// HACK(imjching): We should implement routing policies here.
	substitutionRule string
}

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage:  %s [options]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.StringVar(&options.listenAddress, "listen", "127.0.0.1:5432",
		"Listen address for incoming connections")
	flag.StringVar(&options.cert, "cert-file", "server.crt",
		"file containing PEM-encoded x509 certificate for listen adress")
	flag.StringVar(&options.key, "key-file", "server.key",
		"file containing PEM-encoded x509 key for listen address")
	flag.StringVar(&options.targetAddress, "target", "127.0.0.1:26257",
		"Address to proxy to (a Postgres-compatible server)")
	flag.BoolVar(&options.verify, "verify", true,
		"If true, use InsecureSkipVerify=true for connections to target")
	flag.StringVar(&options.substitutionRule, "substitution-rule", "",
		"Substitution rule for the routing table")
	flag.Parse()

	// TODO(imjching): Implement routing policies. Examples are routing
	// tables (in which a file of mappings is provided), and substitution
	// policies (in which a string with a specific format is provided).
	// Assume that we use a substitution rule for now.
	if options.substitutionRule == "" {
		return fmt.Errorf("missing substitution rule")
	}

	ln, err := net.Listen("tcp", options.listenAddress)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Println("Listening on", ln.Addr())

	cer, err := tls.LoadX509KeyPair(options.cert, options.key)
	if err != nil {
		return err
	}
	opts := proxy.Options{
		IncomingTLSConfig: &tls.Config{Certificates: []tls.Certificate{cer}},
		OutgoingTLSConfig: &tls.Config{InsecureSkipVerify: !options.verify},
		OutgoingAddrFromParams: func(params map[string]string) (addr string, clientErr error) {
			// TODO(asubiotto): implement the actual translation here once it is clear
			// how this will work. It's likely that a filename will be passed to the
			// proxy which contains a lookup map (and which needs to be re-read on
			// SIGHUP). For now, just send everybody to one address and don't validate
			// any parameters.
			// TODO(asubiotto): implement and test the free tier logic:
			// 1. check the 'database' key. The value either contains no dot, and is
			// treated as the tenant name (i.e. the actual database name is empty). 2.
			// if it contains a dot, the tenant name precedes the first dot. Examples:
			// prancing-koala.mydb has tenant name "prancing-koala" and data- base
			// mydb (which will have to be written into the map) and "prancing-koala"
			// has the same tenant name but an empty database.
			log.Println("params", params)

			tenantName, err := extractTenantName(params)
			if err != nil {
				// Cluster name was not embedded at all, whether it is in the
				// default database name, or PG connection option.
				return "", fmt.Errorf("invalid cluster name: %v", err)
			}

			// TODO(imjching): Fix sketchy string replacement approach.
			// TODO(imjching): Verify that the DNS lookup will be cached locally
			// in Kubernetes nodes.
			log.Println("proxying to", strings.ReplaceAll(options.substitutionRule, "{{.tenantName}}", tenantName))
			return strings.ReplaceAll(options.substitutionRule, "{{.tenantName}}", tenantName), nil
		},
	}

	return proxy.Serve(ln, opts)
}

// extractTenantName extracts the cluster name from the connection parameters.
// TODO(imjching): Better UX? Embed go code along with routing policies?
// Using cluster name in the default database name is free tier specific.
func extractTenantName(params map[string]string) (string, error) {
	database, ok := params["database"]
	if !ok {
		return "", fmt.Errorf("could not find database key")
	}
	parts := strings.Split(database, ".")
	if len(parts) != 2 || parts[0] == "" {
		log.Println(parts)
		// This assumes that a regular database name cannot include the dot.
		return "", fmt.Errorf("malformed database key")
	}
	params["database"] = parts[1]
	return parts[0], nil
}
