package main

import (
    "log"
    "github.com/gin-gonic/gin"
)

func main() {
    log.Println("EDR Server Starting...")
    
    router := gin.Default()
    
    router.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })
    
    router.Run(":5000")
}