package paranoidhttp

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// DefaultClient is the default Client whose setting is the same as http.DefaultClient.
var DefaultClient *http.Client

var (
	netPrivateClassA *net.IPNet
	netPrivateClassB *net.IPNet
	netPrivateClassC *net.IPNet
	netTestNet       *net.IPNet
	net6To4Relay     *net.IPNet
)

func init() {
	var err error
	_, netPrivateClassA, err = net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		log.Fatalf("10.0.0.0/8 must be parsed")
	}
	_, netPrivateClassB, err = net.ParseCIDR("172.16.0.0/12")
	if err != nil {
		log.Fatalf("172.16.0.0/12 must be parsed")
	}
	_, netPrivateClassC, err = net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		log.Fatalf("192.168.0.0/16 must be parsed")
	}
	_, netTestNet, err = net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		log.Fatalf("192.0.2.0/24 must be parsed")
	}
	_, net6To4Relay, err = net.ParseCIDR("192.88.99.0/24")
	if err != nil {
		log.Fatalf("192.88.99.0/24 must be parsed")
	}

	DefaultClient, _, _ = NewClient()
}

// NewDialer returns a dialer function which only allows IPv4 connections.
//
// This is used to create a new paranoid http.Client,
// because I'm not sure about a paranoid behavior for IPv6 connections :(
func NewDialer(dialer *net.Dialer) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4":
			return dialer.Dial("tcp4", addr)
		default:
			return nil, errors.New("does not support any networks except tcp4")
		}
	}
}

// NewClient returns a new http.Client configured to be paranoid for attackers.
//
// This also returns http.Tranport and net.Dialer so that you can customize those behavior.
func NewClient() (*http.Client, *http.Transport, *net.Dialer) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Dial:                NewDialer(dialer),
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: NewTransport(transport),
	}, transport, dialer
}

// NewTransport returns a new http.Tranport configured to be pranoid for attackers.
func NewTransport(t *http.Transport) http.RoundTripper {
	return &transport{transport: t}
}

type transport struct {
	transport *http.Transport
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	hostport := req.URL.Host

	errorWithClose := func(err error) (*http.Response, error) {
		if req.Body != nil {
			req.Body.Close()
		}
		log.Print(err)
		return nil, err
	}

	var host string
	if strings.LastIndex(hostport, ":") > strings.LastIndex(hostport, "]") { // hasPort
		h, _, err := net.SplitHostPort(hostport)
		if err != nil {
			return errorWithClose(err)
		}
		host = h
	} else {
		host = hostport
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil && isBadIPv4(ip) {
			return errorWithClose(fmt.Errorf("bad ip is detected: %v", ip))
		}
	} else {
		if isBadHost(host) {
			return errorWithClose(fmt.Errorf("bad host is detected: %v", host))
		}

		ips, err := net.LookupIP(host) // TODO timeout
		if err != nil {
			return errorWithClose(err)
		}
		for _, ip := range ips {
			if ip.To4() != nil && isBadIPv4(ip) {
				return errorWithClose(fmt.Errorf("bad ip is detected: %v", ip))
			}
		}
	}

	return t.transport.RoundTrip(req)
}

func (t *transport) CancelRequest(req *http.Request) {
	t.transport.CancelRequest(req)
}

var regLocalhost = regexp.MustCompile("(?i)^localhost$")
var regHasSpace = regexp.MustCompile("(?i)\\s+")

func isBadHost(host string) bool {
	if regLocalhost.MatchString(host) {
		return true
	}
	if regHasSpace.MatchString(host) {
		return true
	}

	return false
}

func isBadIPv4(ip net.IP) bool {
	if ip.To4() == nil {
		panic("cannot be called for IPv6")
	}

	if ip.Equal(net.IPv4bcast) || !ip.IsGlobalUnicast() ||
		netPrivateClassA.Contains(ip) || netPrivateClassB.Contains(ip) || netPrivateClassC.Contains(ip) ||
		netTestNet.Contains(ip) || net6To4Relay.Contains(ip) {
		return true
	}

	return false
}
