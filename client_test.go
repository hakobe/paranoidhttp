package paranoidhttp

import (
	"net"
	"testing"
)

func TestRequest(t *testing.T) {
	resp, err := DefaultClient.Get("http://www.example.org")
	if err != nil && resp.StatusCode == 200 {
		t.Error("The request with an ordinal url should be successful")
	}

	resp, err = DefaultClient.Get("http://localhost")
	if err == nil {
		t.Errorf("The request for localhost should be fail")
	}

	if _, err := DefaultClient.Get("http://192.168.0.1"); err == nil {
		t.Errorf("The request for localhost should be fail")
	}

	if _, err := DefaultClient.Get("http://[::]"); err == nil {
		t.Errorf("The request for IPv6 unspecified address should be fail")
	}
	if _, err := DefaultClient.Get("http://[fd00::1234]"); err == nil {
		t.Errorf("The request for IPv6 ULA should fail")
	}
}

func TestIsHostForbidden(t *testing.T) {
	badHosts := []string{
		"localhost",
		"host has space",
	}

	for _, h := range badHosts {
		if !basicConfig().isHostForbidden(h) {
			t.Errorf("%s should be forbidden", h)
		}
	}

	notBadHosts := []string{
		"www.hatena.ne.jp",
		"www.google.com",
		"xn--t8jx73hngb.jp",
	}

	for _, h := range notBadHosts {
		if basicConfig().isHostForbidden(h) {
			t.Errorf("%s should not be forbidden", h)
		}
	}
}

func TestIsIpForbidden(t *testing.T) {
	badIPs := []string{
		"0.0.0.0", "::", // Unspecified
		"127.0.0.0", "127.255.255.255", "::1", // Loopback
		"10.0.0.0", "10.255.255.255", // Private A
		"172.16.0.0", "172.31.255.255", // Private B
		"192.168.0.0", "192.168.255.255", // Private C
		"fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // Private v6
		"192.0.2.0", "192.0.2.255", // Test-Net
		"192.88.99.0", "192.88.99.255", // 6to4 relay
		"224.0.0.0", "239.255.255.255", // Multicast
		"ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", //Multicast 6
		"169.254.0.0", "169.254.255.255", // Link local
		"fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // Link Local v6
		"::ffff:0:255.255.255.255", "::ffff:255.255.255.255", //v4 to v6 mapping
		"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", //v6 documentation
	}

	for _, ip := range badIPs {
		if !basicConfig().isIPForbidden(net.ParseIP(ip)) {
			t.Errorf("%s should be forbidden", ip)
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
		"2000::1", "3fff::1",
		// real examples
		"2606:4700:4700::1111", "2001:4860:4860::8888",
	}

	for _, ip := range notBadIPs {
		if basicConfig().isIPForbidden(net.ParseIP(ip)) {
			t.Errorf("%s should not be forbidden", ip)
		}
	}

	c := basicConfig()
	ip := "172.18.0.1"
	if !c.isIPForbidden(net.ParseIP(ip)) {
		t.Errorf("%s should be forbidden", ip)
	}

	c.PermittedIPNets = append(c.PermittedIPNets, mustParseCIDR("172.18.0.1/32"))
	if c.isIPForbidden(net.ParseIP(ip)) {
		t.Errorf("%s should not be forbidden", ip)
	}
}
