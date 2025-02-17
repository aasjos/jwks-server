package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const KeyExpiry = 10 * time.Minute

// JWK represents a JSON Web Key
type JWK struct {
	KID       string `json:"kid"`
	Alg       string `json:"alg"`
	Kty       string `json:"kty"`
	Use       string `json:"use"`
	N         string `json:"n"`
	E         string `json:"e"`
	ExpiresAt int64  `json:"expires_at"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyPair stores the RSA private key and its corresponding public JWK along with an expiration.
type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  JWK
	ExpiresAt  time.Time
}

var (
	keyMutex sync.Mutex
	keys     = make(map[string]KeyPair)
)

// generateKeyPair creates a new RSA key pair with an expiration time in the future.
func generateKeyPair() KeyPair {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key: %v", err)
	}
	kid := uuid.New().String()
	n := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())
	eBytes := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	return KeyPair{
		PrivateKey: privateKey,
		PublicKey: JWK{
			KID:       kid,
			Alg:       "RS256",
			Kty:       "RSA",
			Use:       "sig",
			N:         n,
			E:         e,
			ExpiresAt: time.Now().Add(KeyExpiry).Unix(),
		},
		ExpiresAt: time.Now().Add(KeyExpiry),
	}
}

// getJWKS returns only the keys that have not expired.
func getJWKS(c *gin.Context) {
	keyMutex.Lock()
	defer keyMutex.Unlock()

	var activeKeys []JWK
	for _, key := range keys {
		if time.Now().Before(key.ExpiresAt) {
			activeKeys = append(activeKeys, key.PublicKey)
		}
	}
	c.JSON(http.StatusOK, gin.H{"keys": activeKeys})
}
 

// authHandler issues a JWT signed with either a valid or expired key.
// If the "expired" query parameter is present, it selects an expired key.
func authHandler(c *gin.Context) {
	expiredQuery := c.Query("expired")
	var selectedKey KeyPair

	keyMutex.Lock()
	defer keyMutex.Unlock()

	if expiredQuery != "" {
		// Look for an expired key.
		for _, key := range keys {
			if time.Now().After(key.ExpiresAt) {
				selectedKey = key
				break
			}
		}
		if selectedKey.PrivateKey == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No expired key available"})
			return
		}
	} else {
		// Select a valid key.
		for _, key := range keys {
			if time.Now().Before(key.ExpiresAt) {
				selectedKey = key
				break
			}
		}
		if selectedKey.PrivateKey == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No valid key found"})
			return
		}
	}

	// Set token expiration: if using an expired key, token's exp is set in the past.
	var tokenExpiry time.Time
	if expiredQuery != "" {
		tokenExpiry = time.Now().Add(-5 * time.Minute)
	} else {
		tokenExpiry = time.Now().Add(5 * time.Minute)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "fake_user",
		"exp": tokenExpiry.Unix(),
	})
	token.Header["kid"] = selectedKey.PublicKey.KID

	signedToken, err := token.SignedString(selectedKey.PrivateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": signedToken})
}

// setupServer initializes the server without blocking execution
func setupServer() *gin.Engine {
	r := gin.Default()
	r.GET("/jwks", getJWKS)
	r.POST("/auth", authHandler)
	return r
}

// main starts the server (used for production)
func main() {
	r := setupServer()
	log.Println("JWKS Server running on port 8080")
	r.Run(":8080") // Runs the server
}
