package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TestMain ensures keys are generated before tests run.
func TestMain(m *testing.M) {
	// Initialize keys globally before running tests.
	keyMutex.Lock()
	validKey := generateKeyPair()
	keys[validKey.PublicKey.KID] = validKey

	expiredKey := generateKeyPair()
	expiredKey.ExpiresAt = time.Now().Add(-KeyExpiry) // Make expired
	expiredKey.PublicKey.ExpiresAt = expiredKey.ExpiresAt.Unix()
	keys[expiredKey.PublicKey.KID] = expiredKey
	keyMutex.Unlock()

	// Run tests
	os.Exit(m.Run())
}

// setupRouter initializes the Gin router with our endpoints for testing.
func setupRouter() *gin.Engine {
	r := gin.Default()
	r.GET("/jwks", getJWKS)
	r.POST("/auth", authHandler)
	return r
}

func TestMainFunctionRuns(t *testing.T) {
	router := setupServer()
	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(500 * time.Millisecond)

	// Test if the server is responding
	resp, err := http.Get("http://localhost:8080/jwks")
	if err != nil {
		t.Fatalf("Server did not start properly: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 from /jwks, got %d", resp.StatusCode)
	}

	// Shutdown the server after test
	if err := srv.Close(); err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
}

	 


//  Test `/auth` returns a valid JWT
func TestAuthEndpointValidToken(t *testing.T) {
	router := setupRouter()
	req, _ := http.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Error unmarshaling response: %v", err)
	}

	tokenString, exists := response["token"]
	if !exists {
		t.Fatal("Token not found in response")
	}

	// Parse the token without verifying expiration.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, jwt.ErrTokenMalformed
		}
		keyMutex.Lock()
		defer keyMutex.Unlock()
		keyPair, exists := keys[kid]
		if !exists {
			return nil, jwt.ErrTokenMalformed
		}
		return &keyPair.PrivateKey.PublicKey, nil
	}, jwt.WithoutClaimsValidation())

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}
	if !token.Valid {
		t.Error("Token is invalid")
	}
}

//  Test `/auth?expired=true` returns an expired JWT
func TestAuthEndpointExpiredToken(t *testing.T) {
	router := setupRouter()
	req, _ := http.NewRequest("POST", "/auth?expired=true", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Error unmarshaling response: %v", err)
	}

	tokenString, exists := response["token"]
	if !exists {
		t.Fatal("Token not found in response")
	}

	// Parse the token without verifying expiration.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, jwt.ErrTokenMalformed
		}
		keyMutex.Lock()
		defer keyMutex.Unlock()
		keyPair, exists := keys[kid]
		if !exists {
			return nil, jwt.ErrTokenMalformed
		}
		return &keyPair.PrivateKey.PublicKey, nil
	}, jwt.WithoutClaimsValidation())

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}
	if !token.Valid {
		t.Error("Token is invalid")
	}

	// Ensure expiration time is in the past
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to get claims from token")
	}
	exp := int64(claims["exp"].(float64))
	if time.Now().Unix() < exp {
		t.Error("Token expiration is not in the past for an expired token")
	}
}

//  Test `/auth` fails when no keys exist
func TestAuthFailsWhenNoKeysAvailable(t *testing.T) {
	keyMutex.Lock()
	keys = make(map[string]KeyPair) // Clear all keys
	keyMutex.Unlock()

	router := setupRouter()
	req, _ := http.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected status 500, got %d", w.Code)
	}
}

//  Test `/auth?expired=true` fails when no expired key exists
func TestAuthFailsWhenNoExpiredKeyExists(t *testing.T) {
	keyMutex.Lock()
	keys = make(map[string]KeyPair) // Remove all keys
	validKey := generateKeyPair()
	keys[validKey.PublicKey.KID] = validKey // Add only a valid key
	keyMutex.Unlock()

	router := setupRouter()
	req, _ := http.NewRequest("POST", "/auth?expired=true", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected status 500, got %d", w.Code)
	}
}

//  Test `/jwks` returns empty when no keys exist
func TestJWKSReturnsEmptyWhenNoKeysAvailable(t *testing.T) {
	keyMutex.Lock()
	keys = make(map[string]KeyPair) // Clear all keys
	keyMutex.Unlock()

	router := setupRouter()
	req, _ := http.NewRequest("GET", "/jwks", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var response map[string][]JWK
	json.Unmarshal(w.Body.Bytes(), &response)
	if len(response["keys"]) != 0 {
		t.Fatal("JWKS should return empty keys when no valid keys exist")
	}
}
