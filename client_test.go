package paranoidhttp

import "testing"
import "net"

func TestRequest(t *testing.T) {
	resp, err := DefaultClient.Get("http://www.example.org")
	if err != nil && resp.StatusCode == 200 {
		t.Error("The request with an ordinal url should be successful")
	}

	resp, err = DefaultClient.Get("http://localhost")
	if err == nil {
		t.Errorf("The request for localhost should be fail")
	}
}

func TestIsBadHost(t *testing.T) {
	badHosts := []string{
		"localhost",
		"host has space",
	}

	for _, h := range badHosts {
		if !isBadHost(h) {
			t.Errorf("%s should be bad", h)
		}
	}

	notBadHosts := []string{
		"www.hatena.ne.jp",
		"www.google.com",
		"xn--t8jx73hngb.jp",
	}

	for _, h := range notBadHosts {
		if isBadHost(h) {
			t.Errorf("%s should not be bad", h)
		}
	}
}

func TestIsBadIPv4(t *testing.T) {
	badIPs := []string{
		"0.0.0.0",                      // Unspecified
		"127.0.0.0", "127.255.255.255", // Loopback
		"10.0.0.0", "10.255.255.255", // Private A
		"172.16.0.0", "172.31.255.255", // Private B
		"192.168.0.0", "192.168.255.255", // Private C
		"192.0.2.0", "192.0.2.255", // Test-Net
		"192.88.99.0", "192.88.99.255", // 6to4 relay
		"224.0.0.0", "239.255.255.255", // Multicast
		"169.254.0.0", "169.254.255.255", // Link local
	}

	for _, ip := range badIPs {
		if !isBadIPv4(net.ParseIP(ip)) {
			t.Errorf("%s should be bad", ip)
		}
	}

	notBadIPs := []string{
		"0.0.0.1", "8.8.8.8",
		"126.255.255.255", "128.0.0.0",
		"9.255.255.255", "11.0.0.0",
		"172.15.255.255", "172.32.0.0",
		"192.167.255.255", "192.169.0.0",
		"192.88.98.255", "192.88.100.0",
		"223.255.255.255", "240.0.0.0",
		"169.253.255.255", "169.255.0.0",
	}

	for _, ip := range notBadIPs {
		if isBadIPv4(net.ParseIP(ip)) {
			t.Errorf("%s should not be bad", ip)
		}
	}
}
