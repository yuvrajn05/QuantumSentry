package main

import (
	"crypto/tls"
	"crypto/x509"
    "crypto/rsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type CertInfo struct {
	Subject            string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeySize      int
	SerialNumber       string
	DNSNames           []string
	IsCA               bool
	KeyUsage           string
    ExtensionOIDs []string
}

func decodeTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

func getGroupName(id uint16) string {
	switch id {

	// Classical groups
	case 0x001d:
		return "X25519"
	case 0x0017:
		return "secp256r1"
	case 0x0018:
		return "secp384r1"
	case 0x0019:
		return "secp521r1"

	// Hybrid PQ + Classical (ML-KEM hybrids)
	case 0x11eb:
		return "SecP256r1MLKEM768"
	case 0x11ec:
		return "X25519MLKEM768"
	case 0x11ed:
		return "SecP384r1MLKEM1024"

	// Pure ML-KEM (Post-Quantum KEMs)
	case 0x0200:
		return "MLKEM512"
	case 0x0201:
		return "MLKEM768"
	case 0x0202:
		return "MLKEM1024"

	default:
		return fmt.Sprintf("Unknown(0x%04x)", id)
	}
}

func getCurveName(id tls.CurveID) string {
	switch id {

	// Classical
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "secp256r1"
	case tls.CurveP384:
		return "secp384r1"
	case tls.CurveP521:
		return "secp521r1"

	// Hybrid PQ (manual mapping)
	case tls.CurveID(0x11eb):
		return "SecP256r1MLKEM768"
	case tls.CurveID(0x11ec):
		return "X25519MLKEM768"
	case tls.CurveID(0x11ed):
		return "SecP384r1MLKEM1024"

	// Pure PQ
	case tls.CurveID(0x0200):
		return "MLKEM512"
	case tls.CurveID(0x0201):
		return "MLKEM768"
	case tls.CurveID(0x0202):
		return "MLKEM1024"

	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(id))
	}
}

func extractSupportedGroups(payload []byte) []string {
	var groups []string

	if len(payload) < 43 {
		return groups
	}

	handshake := payload[5:]
	if len(handshake) == 0 || handshake[0] != 0x01 {
		return groups
	}

	idx := 4 + 2 + 32

	if len(handshake) < idx+1 {
		return groups
	}

	sessionIDLen := int(handshake[idx])
	idx += 1 + sessionIDLen

	if len(handshake) < idx+2 {
		return groups
	}

	csLen := int(handshake[idx])<<8 | int(handshake[idx+1])
	idx += 2 + csLen

	if len(handshake) < idx+1 {
		return groups
	}

	compLen := int(handshake[idx])
	idx += 1 + compLen

	if len(handshake) < idx+2 {
		return groups
	}

	extLen := int(handshake[idx])<<8 | int(handshake[idx+1])
	idx += 2

	end := idx + extLen
	if end > len(handshake) {
		end = len(handshake)
	}

	for idx+4 <= end {
		extType := int(handshake[idx])<<8 | int(handshake[idx+1])
		extSize := int(handshake[idx+2])<<8 | int(handshake[idx+3])
		idx += 4

		if idx+extSize > len(handshake) {
			return groups
		}

		// Supported Groups extension
		if extType == 0x000a {
			if extSize < 2 {
				return groups
			}

			listLen := int(handshake[idx])<<8 | int(handshake[idx+1])
			pos := idx + 2

			for pos+1 < idx+2+listLen {
				groupID := uint16(handshake[pos])<<8 | uint16(handshake[pos+1])
				groups = append(groups, getGroupName(groupID))
				pos += 2
			}
		}

		idx += extSize
	}

	return groups
}

func extractSNI(payload []byte) string {
	if len(payload) < 43 {
		return ""
	}

	handshake := payload[5:]
	if len(handshake) == 0 || handshake[0] != 0x01 {
		return ""
	}

	idx := 4 + 2 + 32

	if len(handshake) < idx+1 {
		return ""
	}

	sessionIDLen := int(handshake[idx])
	idx += 1 + sessionIDLen

	if len(handshake) < idx+2 {
		return ""
	}

	csLen := int(handshake[idx])<<8 | int(handshake[idx+1])
	idx += 2 + csLen

	if len(handshake) < idx+1 {
		return ""
	}

	compLen := int(handshake[idx])
	idx += 1 + compLen

	if len(handshake) < idx+2 {
		return ""
	}

	extLen := int(handshake[idx])<<8 | int(handshake[idx+1])
	idx += 2

	end := idx + extLen
	if end > len(handshake) {
		end = len(handshake)
	}

	for idx+4 <= end {
		extType := int(handshake[idx])<<8 | int(handshake[idx+1])
		extSize := int(handshake[idx+2])<<8 | int(handshake[idx+3])
		idx += 4

		if idx+extSize > len(handshake) {
			return ""
		}

		if extType == 0x0000 {
			if extSize < 5 {
				return ""
			}
			nameLen := int(handshake[idx+3])<<8 | int(handshake[idx+4])
			if idx+5+nameLen > len(handshake) {
				return ""
			}
			return string(handshake[idx+5 : idx+5+nameLen])
		}

		idx += extSize
	}

	return ""
}

func getExtensionOIDs(cert *x509.Certificate) []string {
	var oids []string
	for _, ext := range cert.Extensions {
		oids = append(oids, ext.Id.String())
	}
	return oids
}

func certToInfo(cert *x509.Certificate) CertInfo {
	return CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeySize:      getPublicKeySize(cert),
		SerialNumber:       cert.SerialNumber.Text(16),
		DNSNames:           cert.DNSNames,
		IsCA:               cert.IsCA,
		KeyUsage:           parseKeyUsage(cert.KeyUsage),
        ExtensionOIDs: getExtensionOIDs(cert),
	}
}

func parseKeyUsage(usage x509.KeyUsage) string {
	var usages []string

	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}

	if len(usages) == 0 {
		return "Unknown"
	}

	return strings.Join(usages, ", ")
}

func getPublicKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.Size() * 8
	case *ecdsa.PublicKey:
		return pub.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func printCertInfo(info CertInfo) {
	fmt.Println("---- Server Certificate ----")
	fmt.Printf("Subject: %s\n", info.Subject)
	fmt.Printf("Issuer: %s\n", info.Issuer)
	fmt.Printf("Valid From: %s\n", info.NotBefore.Format(time.RFC3339))
	fmt.Printf("Valid To: %s\n", info.NotAfter.Format(time.RFC3339))

	fmt.Printf("Signature Algorithm: %s\n", info.SignatureAlgorithm)
	fmt.Printf("Public Key Algorithm: %s\n", info.PublicKeyAlgorithm)
	fmt.Printf("Public Key Size: %d bits\n", info.PublicKeySize)

	fmt.Printf("Serial Number: %s\n", info.SerialNumber)
	fmt.Printf("Is CA: %t\n", info.IsCA)
	fmt.Printf("Key Usage: %s\n", info.KeyUsage)
    fmt.Printf("Extension OIDs: %v\n", info.ExtensionOIDs)
	if len(info.DNSNames) > 0 {
		fmt.Printf("Primary DNS: %s\n", info.DNSNames[0])
		fmt.Printf("Total DNS Names: %d\n", len(info.DNSNames))
	}

	fmt.Println()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./scanner <target:port>")
		return
	}

	target := os.Args[1]
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		log.Fatal("Invalid target format. Use host:port")
	}

	device := "eth0" // CHANGE THIS if needed

	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("tcp and host %s and port 443", host)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Scanning target:", target)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	certCh := make(chan CertInfo, 1)
	errCh := make(chan error, 1)

	// 🔥 TLS connection goroutine
	go func() {
		conn, err := tls.Dial("tcp", target, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		state := conn.ConnectionState()

		fmt.Println("---- TLS Session Info ----")
		fmt.Printf("TLS Version: %s\n", decodeTLSVersion(state.Version))
		fmt.Printf("Cipher Suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
        selectedGroup := getCurveName(state.CurveID)
        fmt.Printf("Selected Group (KEM): %s\n", selectedGroup)
		if state.NegotiatedProtocol != "" {
			fmt.Printf("ALPN Protocol: %s\n", state.NegotiatedProtocol)
		}
		fmt.Println()

		if len(state.PeerCertificates) == 0 {
			errCh <- fmt.Errorf("no certificate found")
			return
		}

		certCh <- certToInfo(state.PeerCertificates[0])
	}()

	timeout := time.After(8 * time.Second)

	for {
		select {
		case packet := <-packetSource.Packets():
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)

			if ipLayer == nil || tcpLayer == nil {
				continue
			}

			ip := ipLayer.(*layers.IPv4)
			tcp := tcpLayer.(*layers.TCP)

			if len(tcp.Payload) == 0 {
				continue
			}

			payload := tcp.Payload

			if payload[0] == 0x16 {
				fmt.Println("---- TLS Handshake Captured ----")
				fmt.Printf("Target: %s\n", host)
				fmt.Printf("Source IP: %s\n", ip.SrcIP)
				fmt.Printf("Destination IP: %s\n", ip.DstIP)
				sni := extractSNI(payload)
				if sni != "" {
					fmt.Printf("SNI: %s\n", sni)
				}
                groups := extractSupportedGroups(payload)
	            fmt.Printf("Supported Groups: %v\n", groups)
				fmt.Println()
			}

		case cert := <-certCh:
			printCertInfo(cert)
			fmt.Println("Scan complete.")
			return

		case err := <-errCh:
			log.Println("TLS error:", err)
			return

		case <-timeout:
			fmt.Println("Timeout: scan failed")
			return
		}
	}
}