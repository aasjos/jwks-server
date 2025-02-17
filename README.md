# JWKS Server

This project implements a simple JWKS server in Go using the Gin framework. It supports:

- RSA key pair generation with expiration.
- A `/jwks` endpoint that returns only non-expired public keys.
- An `/auth` endpoint that returns a signed JWT.  
  If the `expired` query parameter is present, an expired key is used and the token's expiration is set in the past.

## Running the Server

1. Build and run the server:
   ```bash
   go run main.go
