// Package main — aggregate.go
//
// This file provides read-only analytical endpoints that aggregate data
// across all scan records stored in SQLite.
//
// Endpoints (all require JWT):
//
//	GET /stats          — high-level KPI counters for the Home dashboard
//	GET /cbom/summary   — cipher, key-length, CA, and TLS version distributions
//	GET /posture        — PQC compliance tier breakdown (Elite/Standard/Legacy)
//	GET /cyber-rating   — enterprise 0-1000 score + per-target scores
package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ── /stats ────────────────────────────────────────────────────────────────────

// StatsResponse is the payload for GET /stats.
type StatsResponse struct {
	TotalScans      int `json:"total_scans"`
	SafeCount       int `json:"safe_count"`
	HybridCount     int `json:"hybrid_count"`
	VulnCount       int `json:"vuln_count"`
	TLS13Count      int `json:"tls13_count"`
	TLS12Count      int `json:"tls12_count"`
	ExpiringCerts   int `json:"expiring_certs"`   // certs expiring within 30 days
	HighRiskAssets  int `json:"high_risk_assets"` // vuln verdict count (same as VulnCount here)
	RecentScans     int `json:"recent_scans"`     // scans in last 7 days
}

// handleStats aggregates high-level KPIs from the scans table.
func handleStats(c *gin.Context) {
	records, err := GetHistory(500)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := StatsResponse{TotalScans: len(records)}
	for _, r := range records {
		switch r.Verdict {
		case "safe":
			resp.SafeCount++
		case "hybrid":
			resp.HybridCount++
		case "vuln":
			resp.VulnCount++
			resp.HighRiskAssets++
		}
		if strings.Contains(r.TLSVersion, "1.3") {
			resp.TLS13Count++
		} else if strings.Contains(r.TLSVersion, "1.2") {
			resp.TLS12Count++
		}
	}
	c.JSON(http.StatusOK, resp)
}

// ── /cbom/summary ─────────────────────────────────────────────────────────────

// CBOMSummaryResponse is the payload for GET /cbom/summary.
type CBOMSummaryResponse struct {
	CipherUsage   map[string]int `json:"cipher_usage"`   // cipher_suite → count
	KeyLengths    map[string]int `json:"key_lengths"`     // "2048 bits" → count
	TopCAs        map[string]int `json:"top_cas"`         // issuer CN → count
	TLSVersions   map[string]int `json:"tls_versions"`    // "TLS 1.3" → count
	KEMGroups     map[string]int `json:"kem_groups"`      // selected_group → count
	WeakCrypto    int            `json:"weak_crypto"`     // count of TLS 1.2 / short keys
	ActiveCerts   int            `json:"active_certs"`
	TotalSurveyed int            `json:"total_surveyed"`
	Expiring90    int            `json:"expiring_90"`     // certs expiring within 90 days
	Expiring30    int            `json:"expiring_30"`     // certs expiring within 30 days
}

// handleCBOMSummary iterates all CBOM JSON blobs and aggregates cryptographic data.
func handleCBOMSummary(c *gin.Context) {
	records, err := GetHistory(500) // lightweight — no cbom_json
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := CBOMSummaryResponse{
		CipherUsage: make(map[string]int),
		KeyLengths:  make(map[string]int),
		TopCAs:      make(map[string]int),
		TLSVersions: make(map[string]int),
		KEMGroups:   make(map[string]int),
	}
	resp.TotalSurveyed = len(records)

	for _, r := range records {
		// Fetch full CBOM to extract cipher/cert data.
		full, err := GetScanByID(r.ID)
		if err != nil || full == nil {
			continue
		}

		var cbomRaw struct {
			Assets []struct {
				Protocols []struct {
					CipherSuite   string `json:"cipher_suite"`
					Version       string `json:"version"`
					SelectedGroup string `json:"selected_group"`
				} `json:"protocols"`
				Certificates []struct {
					Issuer        string `json:"issuer"`
					PublicKeySize int    `json:"public_key_size"`
					ValidTo       string `json:"valid_to"`
				} `json:"certificates"`
			} `json:"assets"`
		}
		if err := json.Unmarshal([]byte(full.CBOMJson), &cbomRaw); err != nil {
			continue
		}

		for _, asset := range cbomRaw.Assets {
			for _, proto := range asset.Protocols {
				if proto.CipherSuite != "" {
					resp.CipherUsage[proto.CipherSuite]++
				}
				if proto.Version != "" {
					resp.TLSVersions[proto.Version]++
				}
				if proto.SelectedGroup != "" {
					resp.KEMGroups[proto.SelectedGroup]++
				}
				// Weak crypto: TLS < 1.3
				if strings.Contains(proto.Version, "1.2") || strings.Contains(proto.Version, "1.1") || strings.Contains(proto.Version, "1.0") {
					resp.WeakCrypto++
				}
			}
			for _, cert := range asset.Certificates {
				resp.ActiveCerts++
				// Extract CA CN from issuer string.
				for _, part := range strings.Split(cert.Issuer, ",") {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(strings.ToUpper(part), "CN=") {
						ca := strings.TrimPrefix(strings.TrimPrefix(part, "CN="), "cn=")
						resp.TopCAs[ca]++
					}
				}
				// Key length bucket.
				if cert.PublicKeySize > 0 {
					bucket := keyBucket(cert.PublicKeySize)
					resp.KeyLengths[bucket]++
				}
				// Expiry countdown.
				if cert.ValidTo != "" {
					if exp, err := time.Parse(time.RFC3339, cert.ValidTo); err == nil {
						daysLeft := int(time.Until(exp).Hours() / 24)
						if daysLeft >= 0 && daysLeft <= 90 {
							resp.Expiring90++
						}
						if daysLeft >= 0 && daysLeft <= 30 {
							resp.Expiring30++
						}
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

// keyBucket normalises a key size (bits) into a display bucket string.
func keyBucket(bits int) string {
	switch {
	case bits >= 4096:
		return "4096"
	case bits >= 3072:
		return "3072"
	case bits >= 2048:
		return "2048"
	case bits >= 1024:
		return "1024"
	default:
		return "<1024"
	}
}

// ── /posture ─────────────────────────────────────────────────────────────────

// PostureResponse is the payload for GET /posture.
type PostureResponse struct {
	Elite    int           `json:"elite"`    // safe verdict count
	Standard int           `json:"standard"` // hybrid verdict count
	Legacy   int           `json:"legacy"`   // vuln with TLS 1.2
	Critical int           `json:"critical"` // vuln with TLS 1.0/1.1
	Total    int           `json:"total"`
	Assets   []AssetPosture `json:"assets"`
}

// AssetPosture is a per-target posture row.
type AssetPosture struct {
	Target       string `json:"target"`
	Verdict      string `json:"verdict"`
	VerdictLabel string `json:"verdict_label"`
	TLSVersion   string `json:"tls_version"`
	KEMGroup     string `json:"kem_group"`
	Tier         string `json:"tier"` // "Elite-PQC" | "Standard" | "Legacy" | "Critical"
	Score        int    `json:"score"`
	Timestamp    string `json:"timestamp"`
}

// handlePosture returns PQC posture breakdown across all scanned assets.
func handlePosture(c *gin.Context) {
	records, err := GetHistory(200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := PostureResponse{Total: len(records)}
	// Deduplicate: keep latest scan per target.
	seen := make(map[string]bool)
	for _, r := range records {
		if seen[r.Target] {
			continue
		}
		seen[r.Target] = true

		tier, score := verdictToTier(r.Verdict, r.TLSVersion, r.SelectedGroup)
		switch tier {
		case "Elite-PQC":
			resp.Elite++
		case "Standard":
			resp.Standard++
		case "Legacy":
			resp.Legacy++
		case "Critical":
			resp.Critical++
		}
		resp.Assets = append(resp.Assets, AssetPosture{
			Target:       r.Target,
			Verdict:      r.Verdict,
			VerdictLabel: r.VerdictLabel,
			TLSVersion:   r.TLSVersion,
			KEMGroup:     r.SelectedGroup,
			Tier:         tier,
			Score:        score,
			Timestamp:    r.Timestamp,
		})
	}
	c.JSON(http.StatusOK, resp)
}

// verdictToTier maps verdict → tier label + numeric score.
func verdictToTier(verdict, tlsVersion, kemGroup string) (string, int) {
	isTLS13 := strings.Contains(tlsVersion, "1.3")
	isPQC := strings.Contains(strings.ToUpper(kemGroup), "MLKEM") ||
		strings.Contains(strings.ToUpper(kemGroup), "KYBER")
	isHybrid := strings.HasPrefix(strings.ToUpper(kemGroup), "X25519") && isPQC

	switch {
	case verdict == "safe" && isPQC && isTLS13:
		return "Elite-PQC", 950
	case (verdict == "safe" || verdict == "hybrid") && isTLS13:
		return "Standard", 700
	case verdict == "hybrid" && isHybrid:
		return "Standard", 650
	case verdict == "vuln" && isTLS13:
		return "Legacy", 350
	case verdict == "vuln" && !isTLS13:
		return "Critical", 150
	default:
		return "Legacy", 300
	}
}

// ── /cyber-rating ─────────────────────────────────────────────────────────────

// CyberRatingResponse is the payload for GET /cyber-rating.
type CyberRatingResponse struct {
	EnterpriseScore int                `json:"enterprise_score"` // 0-1000
	Tier            string             `json:"tier"`             // "Legacy" | "Standard" | "Elite-PQC"
	Assets          []AssetRatingEntry `json:"assets"`
}

// AssetRatingEntry is the per-target score row.
type AssetRatingEntry struct {
	Target string `json:"target"`
	Score  int    `json:"score"`
	Tier   string `json:"tier"`
}

// handleCyberRating computes the enterprise-level cyber-rating score.
func handleCyberRating(c *gin.Context) {
	records, err := GetHistory(200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	seen := make(map[string]bool)
	var entries []AssetRatingEntry
	totalScore := 0

	for _, r := range records {
		if seen[r.Target] {
			continue
		}
		seen[r.Target] = true

		_, score := verdictToTier(r.Verdict, r.TLSVersion, r.SelectedGroup)
		tier := scoreTier(score)
		entries = append(entries, AssetRatingEntry{
			Target: r.Target,
			Score:  score,
			Tier:   tier,
		})
		totalScore += score
	}

	// Sort by score descending.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Score > entries[j].Score })

	enterpriseScore := 0
	if len(entries) > 0 {
		enterpriseScore = totalScore / len(entries)
	}

	c.JSON(http.StatusOK, CyberRatingResponse{
		EnterpriseScore: enterpriseScore,
		Tier:            scoreTier(enterpriseScore),
		Assets:          entries,
	})
}

// scoreTier maps a numeric score to a tier label.
func scoreTier(score int) string {
	switch {
	case score >= 700:
		return "Elite-PQC"
	case score >= 400:
		return "Standard"
	default:
		return "Legacy"
	}
}
