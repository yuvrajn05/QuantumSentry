package main

import (
	"bytes"
	"net/http"
	"os/exec"
	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
)

func main() {
	r := gin.Default()
	r.Use(cors.Default())

	r.GET("/", func(c *gin.Context) {
		c.File("../frontend/index.html")
	})
	r.GET("/script.js", func(c *gin.Context) {
		c.File("../frontend/script.js")
	})
	// scan endpoint
	r.GET("/scan", func(c *gin.Context) {
		target := c.Query("target")

		if target == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "target query param required (e.g. ?target=google.com:443)",
			})
			return
		}

		cmd := exec.Command("../scanner/scanner", target)

		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
				"stderr": stderr.String(),
			})
			return
		}

		c.Data(http.StatusOK, "application/json", out.Bytes())
	})
	r.Run(":8080")
}