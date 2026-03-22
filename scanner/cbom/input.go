package cbom

type ScanInput struct {
    Host string

    // Network layer
    SourceIP      string
    DestinationIP string
    SNI           string

    // TLS
    TLSVersion      string
    CipherSuite     string
    SelectedGroup   string
    SupportedGroups []string
    ALPN            string

    // Certificate
    Subject string
    Issuer  string

    ValidFrom string
    ValidTo   string

    SerialNumber string

    SignatureAlgorithm string

    PublicKeyAlgorithm string
    PublicKeySize      int

    IsCA bool

    DNSNames   []string
    DNSCount   int
    PrimaryDNS string

    KeyUsage    []string
    ExtKeyUsage []string

    OIDs []string

    PublicKeyRef string
}