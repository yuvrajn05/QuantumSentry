package cbom

import (
    "fmt"
    "time"
)

func generateScanID(host string) string {
    return fmt.Sprintf("%s-%d", host, time.Now().Unix())
}