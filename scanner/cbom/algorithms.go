package cbom

import "strings"

func ExtractAlgorithms(cipher string) []Algorithm {
    var algos []Algorithm

    c := strings.ToUpper(cipher)

    if strings.Contains(c, "RSA") {
        algos = append(algos, Algorithm{
            Name:            "RSA",
            Primitive:       "asymmetric",
            CryptoFunctions: []string{"encryption", "signature"},
            ClassicalSecBits: 112,
        })
    }

    if strings.Contains(c, "ECDHE") {
        algos = append(algos, Algorithm{
            Name:            "ECDHE",
            Primitive:       "key-exchange",
            CryptoFunctions: []string{"key_agreement"},
        })
    }

    if strings.Contains(c, "AES") {
        mode := ""
        if strings.Contains(c, "GCM") {
            mode = "GCM"
        }

        algos = append(algos, Algorithm{
            Name:            "AES",
            Primitive:       "symmetric",
            Mode:            mode,
            CryptoFunctions: []string{"encryption"},
            ClassicalSecBits: 128,
        })
    }

    if strings.Contains(c, "CHACHA20") {
        algos = append(algos, Algorithm{
            Name:            "ChaCha20",
            Primitive:       "symmetric",
            CryptoFunctions: []string{"encryption"},
            ClassicalSecBits: 256,
        })
    }

    return algos
}