package lib

import (
	"math/rand"
	"net"
	"testing"
)

// GetKey returns a []byte key to be used in test functions
func GetKey(t *testing.T) []byte {
	t.Helper()

	k, _ := GeneratePrivateKey()
	return k.Data[:]
}

// GetPSK returns a []byte PSK to be used in test functions
func GetPSK(t *testing.T) *PresharedKey {
	t.Helper()

	k, _ := GeneratePSK()
	return &k
}

// GetEndpoint returns a random IPv4 UDPAddr to be used in test functions
func GetEndpoint(t *testing.T) *UDPAddr {
	t.Helper()

	ip := []byte{byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255))}
	port := rand.Intn(65000)
	return &UDPAddr{IP: net.IP(ip), Port: port}
}

// GetSubnet returns a random IPv4 IPNet to be used in test functions
func GetSubnet(t *testing.T) IPNet {
	t.Helper()

	ip := net.IP([]byte{byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255)), byte(rand.Intn(255))})
	mask := net.CIDRMask(rand.Intn(32), 32)
	sub := ip.Mask(mask)

	return IPNet(net.IPNet{IP: sub, Mask: mask})
}
