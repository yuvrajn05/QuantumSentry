package cbom

type ScanRun struct {
    ScanID    string  `json:"scan_id"`
    Timestamp string  `json:"timestamp"`
    Target    string  `json:"target"`
    Assets    []Asset `json:"assets"`
}

type Asset struct {
    Host string `json:"host"`

    Network NetworkInfo `json:"network"`

    Protocols    []Protocol    `json:"protocols"`
    Certificates []Certificate `json:"certificates"`
}

type NetworkInfo struct {
    SourceIP      string `json:"source_ip,omitempty"`
    DestinationIP string `json:"destination_ip,omitempty"`
    SNI           string `json:"sni,omitempty"`
}

type Protocol struct {
    Name string `json:"name"`

    Version     string `json:"version"`
    CipherSuite string `json:"cipher_suite"`

    SelectedGroup string   `json:"selected_group,omitempty"`
    SupportedGroups []string `json:"supported_groups,omitempty"`

    ALPN string `json:"alpn,omitempty"`

    Algorithms []Algorithm `json:"algorithms"`
}

type Certificate struct {
    Subject string `json:"subject"`
    Issuer  string `json:"issuer"`

    ValidFrom string `json:"valid_from"`
    ValidTo   string `json:"valid_to"`

    SerialNumber string `json:"serial_number"`

    SignatureAlgorithm string `json:"signature_algorithm"`

    PublicKeyAlgorithm string `json:"public_key_algorithm"`
    PublicKeySize      int    `json:"public_key_size"`

    IsCA bool `json:"is_ca"`

    DNSNames     []string `json:"dns_names,omitempty"`
    DNSCount     int      `json:"dns_count,omitempty`
    PrimaryDNS   string   `json:"primary_dns,omitempty"`

    KeyUsage    []string `json:"key_usage,omitempty"`
    ExtKeyUsage []string `json:"ext_key_usage,omitempty"`

    OIDs []string `json:"oids,omitempty"`

    PublicKeyRef string `json:"public_key_ref,omitempty"`
}

type Algorithm struct {
    Name             string   `json:"name"`
    Primitive        string   `json:"primitive"`
    Mode             string   `json:"mode,omitempty"`
    CryptoFunctions  []string `json:"crypto_functions,omitempty"`
    ClassicalSecBits int      `json:"security_bits,omitempty"`
}