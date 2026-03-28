// Package main implements the QuantumSentry backend API server.
//
// It is a lightweight Go HTTP server (powered by Gin) that serves the
// frontend dashboard and exposes REST endpoints:
//
//	GET  /scan?target=<host:port>   — run a scan, persist result, return CBOM JSON
//	GET  /history                   — list last 50 scans (newest first)
//	GET  /history/:id               — fetch full CBOM for a specific scan
//	GET  /audit                     — last 200 audit log entries
//
// Every request is recorded in the audit_log table for compliance traceability.
// Scan results are persisted in SQLite (quantumsentry.db) for history tracking.
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Initialise SQLite database (creates file + tables if they don't exist).
	InitDB()

	r := gin.Default()

	// Allow cross-origin requests for development.
	r.Use(cors.Default())

	// ── Audit middleware — log every API request ───────────────────────────
	r.Use(func(c *gin.Context) {
		c.Next() // process request first

		// Only audit API paths (skip static files)
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/scan") ||
			strings.HasPrefix(path, "/history") ||
			strings.HasPrefix(path, "/audit") {

			status := "OK"
			if c.Writer.Status() >= 400 {
				status = "ERROR"
			}
			target := c.Query("target")
			if target == "" {
				target = c.Param("id")
			}
			LogAudit(
				strings.ToUpper(strings.TrimPrefix(path, "/")),
				target,
				status,
				"",
			)
		}
	})

	// ── Static frontend routes ────────────────────────────────────────────
	r.GET("/", func(c *gin.Context) {
		c.File("../frontend/index.html")
	})
	r.GET("/script.js", func(c *gin.Context) {
		c.File("../frontend/script.js")
	})
	r.GET("/style.css", func(c *gin.Context) {
		c.File("../frontend/style.css")
	})

	// ── GET /scan?target=<host:port> ──────────────────────────────────────
	// Runs the scanner, saves the result to the DB, and returns CBOM JSON.
	r.GET("/scan", func(c *gin.Context) {
		target := c.Query("target")
		if target == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "target query param required (e.g. ?target=google.com:443)",
			})
			return
		}

		// Invoke scanner binary as a subprocess.
		cmd := exec.Command("../scanner/scanner.exe", target)
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  err.Error(),
				"stderr": stderr.String(),
			})
			return
		}

		cbomBytes := out.Bytes()

		// Parse just enough of the CBOM to extract fields for DB storage.
		var cbom struct {
			ScanID    string `json:"scan_id"`
			Timestamp string `json:"timestamp"`
			Assets    []struct {
				Protocols []struct {
					Version       string `json:"version"`
					SelectedGroup string `json:"selected_group"`
				} `json:"protocols"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(cbomBytes, &cbom); err == nil && cbom.ScanID != "" {
			// Compute verdict by inspecting the selected KEM group.
			verdict, verdictLabel := computeVerdict(cbom)

			_ = SaveScan(ScanRecord{
				ID:            cbom.ScanID,
				Timestamp:     cbom.Timestamp,
				Target:        target,
				Verdict:       verdict,
				VerdictLabel:  verdictLabel,
				TLSVersion:    safeGet(cbom.Assets, 0),
				SelectedGroup: safeGetGroup(cbom.Assets, 0),
				CBOMJson:      string(cbomBytes),
			})
		}

		// Return raw CBOM to frontend.
		c.Data(http.StatusOK, "application/json", cbomBytes)
	})

	// ── GET /history ──────────────────────────────────────────────────────
	// Returns the last 50 scans (without full CBOM JSON for performance).
	r.GET("/history", func(c *gin.Context) {
		records, err := GetHistory(50)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if records == nil {
			records = []ScanRecord{}
		}
		c.JSON(http.StatusOK, gin.H{"scans": records})
	})

	// ── GET /history/:id ──────────────────────────────────────────────────
	// Returns the full CBOM JSON for a specific scan ID.
	r.GET("/history/:id", func(c *gin.Context) {
		id := c.Param("id")
		rec, err := GetScanByID(id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if rec == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		// Return the raw CBOM JSON stored in the DB.
		c.Data(http.StatusOK, "application/json", []byte(rec.CBOMJson))
	})

	// ── GET /audit ────────────────────────────────────────────────────────
	// Returns the audit trail (last 200 entries).
	r.GET("/audit", func(c *gin.Context) {
		entries, err := GetAuditLog(200)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if entries == nil {
			entries = []AuditRecord{}
		}
		c.JSON(http.StatusOK, gin.H{"entries": entries})
	})

	r.Run(":8080")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// computeVerdict derives a verdict string and label from the CBOM assets.
func computeVerdict(cbom struct {
	ScanID    string `json:"scan_id"`
	Timestamp string `json:"timestamp"`
	Assets    []struct {
		Protocols []struct {
			Version       string `json:"version"`
			SelectedGroup string `json:"selected_group"`
		} `json:"protocols"`
	} `json:"assets"`
}) (string, string) {
	if len(cbom.Assets) == 0 || len(cbom.Assets[0].Protocols) == 0 {
		return "unknown", "Unknown"
	}

	group := cbom.Assets[0].Protocols[0].SelectedGroup

	purePQ := []string{"MLKEM512", "MLKEM768", "MLKEM1024"}
	hybrid := []string{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}

	for _, g := range purePQ {
		if group == g {
			return "safe", "Post-Quantum Safe"
		}
	}
	for _, g := range hybrid {
		if group == g {
			return "hybrid", "Hybrid PQ — Partially Safe"
		}
	}
	return "vuln", "Quantum Vulnerable"
}

func safeGet(assets []struct {
	Protocols []struct {
		Version       string `json:"version"`
		SelectedGroup string `json:"selected_group"`
	} `json:"protocols"`
}, idx int) string {
	if len(assets) > idx && len(assets[idx].Protocols) > 0 {
		return assets[idx].Protocols[0].Version
	}
	return ""
}

func safeGetGroup(assets []struct {
	Protocols []struct {
		Version       string `json:"version"`
		SelectedGroup string `json:"selected_group"`
	} `json:"protocols"`
}, idx int) string {
	if len(assets) > idx && len(assets[idx].Protocols) > 0 {
		return assets[idx].Protocols[0].SelectedGroup
	}
	return ""
}

// nowRFC3339 returns the current UTC time in RFC3339 format.
func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}