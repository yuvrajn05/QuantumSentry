// Package main implements the QuantumSentry backend API server.
//
// It is a lightweight Go HTTP server (powered by Gin) that serves the
// frontend dashboard and exposes a single REST endpoint:
//
//	GET /scan?target=<host:port>
//
// When a scan is triggered, the server invokes the compiled scanner binary
// as a subprocess, captures its CBOM JSON output, and streams it back to
// the caller. This keeps the backend stateless and decoupled from the
// scanning logic.
//
// Usage:
//
//	cd backend && ./server.exe
//	# Server listens on :8080
package main

import (
	"bytes"
	"net/http"
	"os/exec"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// Allow cross-origin requests so the frontend can call this API
	// even when opened from a different origin during development.
	r.Use(cors.Default())

	// ── Static frontend routes ────────────────────────────────────
	r.GET("/", func(c *gin.Context) {
		c.File("../frontend/index.html")
	})
	r.GET("/script.js", func(c *gin.Context) {
		c.File("../frontend/script.js")
	})
	r.GET("/style.css", func(c *gin.Context) {
		c.File("../frontend/style.css")
	})

	// ── Scan endpoint ─────────────────────────────────────────────
	// Accepts: ?target=<host:port>   e.g.  ?target=google.com:443
	// Returns: CBOM JSON produced by the scanner binary, or an error object.
	r.GET("/scan", func(c *gin.Context) {
		target := c.Query("target")

		if target == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "target query param required (e.g. ?target=google.com:443)",
			})
			return
		}

		// Invoke the scanner binary as a subprocess.
		// The scanner writes its CBOM JSON to stdout; errors go to stderr.
		cmd := exec.Command("../scanner/scanner.exe", target)

		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":  err.Error(),
				"stderr": stderr.String(),
			})
			return
		}

		// Forward the scanner's JSON output directly to the client.
		c.Data(http.StatusOK, "application/json", out.Bytes())
	})

	r.Run(":8080")
}