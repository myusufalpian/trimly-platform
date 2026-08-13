package httputil

import (
	"net"
	"net/http"
	"strings"
)

type TrustedProxyExtractor struct {
	trustedNets []*net.IPNet
}

func NewTrustedProxyExtractor(cidrs []string) (*TrustedProxyExtractor, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		if strings.TrimSpace(cidr) == "" {
			continue
		}
		ipNet, err := parseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipNet)
	}
	return &TrustedProxyExtractor{trustedNets: nets}, nil
}

func parseCIDR(cidr string) (*net.IPNet, error) {
	if strings.Contains(cidr, "/") {
		_, ipNet, err := net.ParseCIDR(cidr)
		return ipNet, err
	}
	ip := net.ParseIP(cidr)
	if ip == nil {
		return nil, &net.ParseError{Type: "IP address", Text: cidr}
	}
	if ip.To4() != nil {
		return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

func hostOnly(value string) string {
	value = strings.TrimSpace(value)
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return value
	}
	return host
}

// ClientIP returns the real client IP. Forwarded headers are only trusted when
// the direct peer (RemoteAddr) is inside one of the configured trusted proxy CIDRs.
// Forwarded values must be plain IPs (no ports). Multi-hop X-Forwarded-For is not
// resolved: the leftmost value is used, so trusted proxies must overwrite the
// header rather than append to it.
func (e *TrustedProxyExtractor) ClientIP(r *http.Request) string {
	if !e.isTrustedPeer(r) {
		return GetRemoteIP(r)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return hostOnly(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return hostOnly(xrip)
	}
	return GetRemoteIP(r)
}

func (e *TrustedProxyExtractor) isTrustedPeer(r *http.Request) bool {
	peer := net.ParseIP(GetRemoteIP(r))
	if peer == nil {
		return false
	}
	for _, n := range e.trustedNets {
		if n.Contains(peer) {
			return true
		}
	}
	return false
}
