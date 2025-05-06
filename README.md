# i6.shark

An IPv6 proxy server that allows you to make HTTP requests from randomly generated IPv6 addresses in a /48 subnet. This project basically built the best proxy on earth, a /48 subnet has `1,208,925,819,614,629,174,706,176` (1.2 × 10²⁴) IPv6 addresses, which if you can't tell is a lot. Using a single subnet means those who really want to block you can block your ASN address, so be careful with that. This project is designed to be used for educational purposes only, and should not be used for any illegal activities (totally).

## Features

- Generates random IPv6 addresses based on your IPv6 prefix
- API key authentication for secure usage
- Full HTTP method support (GET, POST, PUT, DELETE, etc.)

## Requirements

- Go 1.20 or higher
- Linux/Unix system with IPv6 support
- Root privileges (for port 80 binding and IPv6 manipulation)

## Configuration

Edit the constants at the top of the `main.go` file:

```go
const (
	SharedSecret       = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // Secret between client & server
	Version            = "2.2"                              // Version of the script
	IPv6Prefix         = "xxxx:xxxx:xxxx"                   // Your /48 prefix
	IPv6Subnet         = "1000"                             // Using subnet 1000 within your /48
	Interface          = "ens3"                             // Detected interface from your system
	ListenPort         = 80                                 // Proxy server port
	ListenHost         = "0.0.0.0"                          // Listen on all interfaces
	PublicURL          = ""                                 // Public URL for proxy endpoints (empty to use request host)
	RequireAuth        = true                               // Set to false to disable API token authentication
	RequestTimeout     = 30 * time.Second                   // Request timeout in seconds
	Debug              = false                              // Enable debug output
	DesiredPoolSize    = 100                                // Target number of IPs in the pool
	PoolManageInterval = 5 * time.Second                    // Check/add less frequently (every 5 seconds)
	PoolAddBatchSize   = 5                                  // Try to add up to 5 IPs per cycle if needed
)
```

## Usage

1. Build the application:
```
go build -o i6shark
```

2. Run with root privileges:
```
sudo ./i6shark
```

3. Send requests through the proxy:
```
# For general proxy requests
curl "http://localhost/?destination=https://example.com" -H "API-Token: VALID_API_TOKEN"

# For m3u8/ts proxy requests
curl "http://localhost/m3u8-proxy?url=https://example.com/playlist.m3u8" -H "API-Token: VALID_API_TOKEN"
curl "http://localhost/ts-proxy?url=https://example.com/segment.ts" -H "API-Token: VALID_API_TOKEN"

# Without authentication (if RequireAuth is set to false)
curl "http://localhost/?destination=https://example.com"
```

4. To include custom headers in the proxy request, add a URL-encoded JSON object as the `headers` parameter:
```
# Adding Referer and Origin headers to an m3u8 proxy request
curl "http://localhost/m3u8-proxy?url=https://example.com/playlist.m3u8&headers=%7B%22referer%22%3A%22https%3A%2F%2Fexample.org%2F%22%2C%22origin%22%3A%22https%3A%2F%2Fexample.org%22%7D" -H "API-Token: VALID_API_TOKEN"
```

The URL-decoded headers parameter in the example above would be:
```json
{"referer":"https://example.org/","origin":"https://example.org"}
```

5. If you're running behind a domain name, set the `PublicURL` constant to your full URL:
```go
PublicURL = "https://proxy.example.com" // Use your actual domain if you are behind a reverse proxy
```

6. To disable API token authentication, set the `RequireAuth` constant to false:
```go
RequireAuth = false // Allow all requests without API-Token
```

## API Authentication

API tokens are generated using HMAC-SHA256 and a secret key the input for the key generation is the user-agent header. See the `validateAPIToken` function for implementation details.
