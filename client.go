package paranoidhttp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"time"
)

// DefaultClient is the default Client whose setting is the same as http.DefaultClient.
var (
	DefaultConfig *Config
	DefaultClient *http.Client
)

func mustParseCIDR(addr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		log.Fatalf("%s must be parsed", addr)
	}
	return ipnet
}

// Config stores the rules for allowing IP/hosts
type Config struct {
	ForbiddenCIDRs []*net.IPNet
	Exceptions     []*net.IPNet
	ForbiddenHosts []*regexp.Regexp
}

// IsHostForbidden checks whether a hostname is forbidden by the Config
func (c *Config) IsHostForbidden(host string) bool {
	for _, forbiddenHost := range c.ForbiddenHosts {
		if forbiddenHost.MatchString(host) {
			return true
		}
	}
	return false
}

// IsIPForbidden checks whether an IP address is forbidden by the Config
func (c *Config) IsIPForbidden(ip net.IP) bool {
	if ip.To4() == nil {
		panic("cannot be called for IPv6")
	}

	for _, exception := range c.Exceptions {
		if exception.Contains(ip) {
			return false
		}
	}

	if ip.Equal(net.IPv4bcast) || !ip.IsGlobalUnicast() {
		return true
	}

	for _, forbiddenCIDR := range c.ForbiddenCIDRs {
		if forbiddenCIDR.Contains(ip) {
			return true
		}
	}
	return false
}

// BasicConfig contains the most common hosts and IPs to be blocked
func BasicConfig() *Config {
	return &Config{
		ForbiddenCIDRs: []*net.IPNet{
			mustParseCIDR("10.0.0.0/8"),     // private class A
			mustParseCIDR("172.16.0.0/12"),  // private class B
			mustParseCIDR("192.168.0.0/16"), // private class C
			mustParseCIDR("192.0.2.0/24"),   // test net 1
			mustParseCIDR("192.88.99.0/24"), // 6to4 relay
		},

		ForbiddenHosts: []*regexp.Regexp{
			regexp.MustCompile("(?i)^localhost$"),
			regexp.MustCompile("(?i)\\s+"),
		},
	}
}

func init() {
	DefaultConfig = BasicConfig()
	DefaultClient, _, _ = NewClient(DefaultConfig)
}

func safeAddr(ctx context.Context, resolver *net.Resolver, config *Config, hostport string) (string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", err
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil && config.IsIPForbidden(ip) {
			return "", fmt.Errorf("bad ip is detected: %v", ip)
		}
		return net.JoinHostPort(ip.String(), port), nil
	}

	if config.IsHostForbidden(host) {
		return "", fmt.Errorf("bad host is detected: %v", host)
	}

	r := resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) <= 0 {
		return "", err
	}
	safeAddrs := make([]net.IPAddr, 0, len(addrs))
	for _, addr := range addrs {
		// only support IPv4 address
		if addr.IP.To4() == nil {
			continue
		}
		if config.IsIPForbidden(addr.IP) {
			return "", fmt.Errorf("bad ip is detected: %v", addr.IP)
		}
		safeAddrs = append(safeAddrs, addr)
	}
	if len(safeAddrs) == 0 {
		return "", fmt.Errorf("fail to lookup ip addr: %v", host)
	}
	return net.JoinHostPort(safeAddrs[0].IP.String(), port), nil
}

// NewDialer returns a dialer function which only allows IPv4 connections.
//
// This is used to create a new paranoid http.Client,
// because I'm not sure about a paranoid behavior for IPv6 connections :(
func NewDialer(dialer *net.Dialer, config *Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, hostport string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4":
			addr, err := safeAddr(ctx, dialer.Resolver, config, hostport)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		default:
			return nil, errors.New("does not support any networks except tcp4")
		}
	}
}

// NewClient returns a new http.Client configured to be paranoid for attackers.
//
// This also returns http.Tranport and net.Dialer so that you can customize those behavior.
func NewClient(config *Config) (*http.Client, *http.Transport, *net.Dialer) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         NewDialer(dialer, config),
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}, transport, dialer
}
