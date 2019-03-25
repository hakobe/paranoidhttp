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

// Config stores the rules for allowing IP/hosts
type config struct {
	ForbiddenCIDRs []*net.IPNet
	AllowCIDRs     []*net.IPNet
	ForbiddenHosts []*regexp.Regexp
}

// DefaultClient is the default Client whose setting is the same as http.DefaultClient.
var (
	defaultConfig config
	DefaultClient *http.Client
)

func mustParseCIDR(addr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		log.Fatalf("%s must be parsed", addr)
	}
	return ipnet
}

func init() {
	defaultConfig = config{
		ForbiddenCIDRs: []*net.IPNet{
			mustParseCIDR("10.0.0.0/8"),     // private class A
			mustParseCIDR("172.16.0.0/12"),  // private class B
			mustParseCIDR("192.168.0.0/16"), // private class C
			mustParseCIDR("192.0.2.0/24"),   // test net 1
			mustParseCIDR("192.88.99.0/24"), // 6to4 relay
		},
		ForbiddenHosts: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^localhost$`),
			regexp.MustCompile(`(?i)\s+`),
		},
	}
	DefaultClient, _, _ = NewClient()
}

// isHostForbidden checks whether a hostname is forbidden by the Config
func (c *config) isHostForbidden(host string) bool {
	for _, forbiddenHost := range c.ForbiddenHosts {
		if forbiddenHost.MatchString(host) {
			return true
		}
	}
	return false
}

// isIPForbidden checks whether an IP address is forbidden by the Config
func (c *config) isIPForbidden(ip net.IP) bool {
	if ip.To4() == nil {
		panic("cannot be called for IPv6")
	}

	for _, allowCIDR := range c.AllowCIDRs {
		if allowCIDR.Contains(ip) {
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
func basicConfig() *config {
	c := defaultConfig // copy to return clone
	return &c
}

// Option type of paranoidhttp
type Option func(*config)

// ForbiddenCIDRs sets forbidden CIDRs
func ForbiddenCIDRs(ips ...*net.IPNet) Option {
	return func(c *config) {
		c.ForbiddenCIDRs = ips
	}
}

// AllowCIDRs sets allow CIDRs
// It takes priority over other forbidden rules.
func AllowCIDRs(ips ...*net.IPNet) Option {
	return func(c *config) {
		c.AllowCIDRs = ips
	}
}

// ForbiddenHosts set forbidden host rules by regexp
func ForbiddenHosts(hostRegs ...*regexp.Regexp) Option {
	return func(c *config) {
		c.ForbiddenHosts = hostRegs
	}
}

func safeAddr(ctx context.Context, resolver *net.Resolver, hostport string, opts ...Option) (string, error) {
	c := basicConfig()
	for _, opt := range opts {
		opt(c)
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", err
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil && c.isIPForbidden(ip) {
			return "", fmt.Errorf("bad ip is detected: %v", ip)
		}
		return net.JoinHostPort(ip.String(), port), nil
	}

	if c.isHostForbidden(host) {
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
		if c.isIPForbidden(addr.IP) {
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
func NewDialer(dialer *net.Dialer, opts ...Option) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, hostport string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4":
			addr, err := safeAddr(ctx, dialer.Resolver, hostport, opts...)
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
func NewClient(opts ...Option) (*http.Client, *http.Transport, *net.Dialer) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         NewDialer(dialer, opts...),
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}, transport, dialer
}
