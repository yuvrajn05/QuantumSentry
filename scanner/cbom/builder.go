package cbom

import "time"

func BuildFromScan(input ScanInput) ScanRun {

    scan := ScanRun{
        ScanID:    generateScanID(input.Host),
        Timestamp: time.Now().Format(time.RFC3339),
        Target:    input.Host,
    }

    asset := Asset{
        Host: input.Host,
        Network: NetworkInfo{
            SourceIP:      input.SourceIP,
            DestinationIP: input.DestinationIP,
            SNI:           input.SNI,
        },
    }

    protocol := Protocol{
        Name: "TLS",

        Version:     input.TLSVersion,
        CipherSuite: input.CipherSuite,

        SelectedGroup:  input.SelectedGroup,
        SupportedGroups: input.SupportedGroups,

        ALPN: input.ALPN,

        Algorithms: ExtractAlgorithms(input.CipherSuite),
    }

    asset.Protocols = []Protocol{protocol}

    cert := Certificate{
        Subject: input.Subject,
        Issuer:  input.Issuer,

        ValidFrom: input.ValidFrom,
        ValidTo:   input.ValidTo,

        SerialNumber: input.SerialNumber,

        SignatureAlgorithm: input.SignatureAlgorithm,

        PublicKeyAlgorithm: input.PublicKeyAlgorithm,
        PublicKeySize:      input.PublicKeySize,

        IsCA: input.IsCA,

        DNSNames:   input.DNSNames,
        DNSCount:   input.DNSCount,
        PrimaryDNS: input.PrimaryDNS,

        KeyUsage:    input.KeyUsage,
        ExtKeyUsage: input.ExtKeyUsage,

        OIDs: input.OIDs,

        PublicKeyRef: input.PublicKeyRef,
    }

    asset.Certificates = []Certificate{cert}

    scan.Assets = []Asset{asset}

    return scan
}