# i6.shark / Complex IPv6 Proxy

An IPv6 proxy server that allows you to make HTTP requests from randomly generated IPv6 addresses in a /48 subnet. This project basically built the best proxy on earth, a /48 subnet has `1,208,925,819,614,629,174,706,176` (1.2 × 10²⁴) IPv6 addresses, which if you can't tell is a lot. Using a single subnet means those who really want to block you can block your ASN address, so be careful with that. This project is designed to be used for educational purposes only, and should not be used for any illegal activities (totally).

## Features

- Generates random IPv6 addresses based on your IPv6 prefix
- API key authentication for secure usage
- Full HTTP method support (GET, POST, PUT, DELETE, etc.)
- Docker support for easy deployment
- Environment variable configuration

## Requirements

### Running Directly
- Go 1.20 or higher
- Linux/Unix system with IPv6 support
- Root privileges (for port 80 binding and IPv6 manipulation)

### Running with Docker
- Docker and Docker Compose
- IPv6 support on your host machine
- CAP_NET_ADMIN capability for the container

## Configuration

### Option 1: Environment Variables (Recommended)
All configuration is handled through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| SHARED_SECRET | Secret between client & server | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |
| VERSION | Version of the script | 2.2 |
| IPV6_PREFIX | Your /48 IPv6 prefix | 2a01:e5c0:2d74 |
| IPV6_SUBNET | Subnet within your IPv6 prefix | 5000 |
| INTERFACE | Network interface name | ens3 (eth0 in container) |
| LISTEN_PORT | Port on which the proxy listens | 80 |
| LISTEN_HOST | Host address to listen on | 0.0.0.0 |
| PUBLIC_URL | Public URL for proxy endpoints (empty to use request host) | |
| REQUIRE_AUTH | Whether to require API token authentication | true |
| REQUEST_TIMEOUT | Request timeout in seconds | 30 |
| DEBUG | Enable detailed debug output | false |
| DESIRED_POOL_SIZE | Target number of IPs in the pool | 1000 |
| POOL_MANAGE_INTERVAL | Interval for checking/adding IPs (seconds) | 5 |
| POOL_ADD_BATCH_SIZE | How many IPs to add per cycle if needed | 15 |

### Option 2: Direct Constants (Legacy)
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

### Running Directly

1. Build the application:
```
go build -o i6shark src/main.go
```

2. Run with root privileges:
```
sudo ./i6shark
```

### Running with Docker

1. Clone this repository
2. Copy the example environment file:
   ```
   cp .env.example .env
   ```
3. Edit the `.env` file to configure your environment
4. Build and start the container:
   ```
   docker-compose up -d
   ```

### Making Proxy Requests

1. Send requests through the proxy:
```
# For general proxy requests
curl "http://localhost/?destination=https://example.com" -H "API-Token: VALID_API_TOKEN"

# For m3u8/ts proxy requests
curl "http://localhost/m3u8-proxy?url=https://example.com/playlist.m3u8" -H "API-Token: VALID_API_TOKEN"
curl "http://localhost/ts-proxy?url=https://example.com/segment.ts" -H "API-Token: VALID_API_TOKEN"

# Without authentication (if RequireAuth is set to false)
curl "http://localhost/?destination=https://example.com"
```

2. To include custom headers in the proxy request, add a URL-encoded JSON object as the `headers` parameter:
```
# Adding Referer and Origin headers to an m3u8 proxy request
curl "http://localhost/m3u8-proxy?url=https://example.com/playlist.m3u8&headers=%7B%22referer%22%3A%22https%3A%2F%2Fexample.org%2F%22%2C%22origin%22%3A%22https%3A%2F%2Fexample.org%22%7D" -H "API-Token: VALID_API_TOKEN"
```

The URL-decoded headers parameter in the example above would be:
```json
{"referer":"https://example.org/","origin":"https://example.org"}
```

## API Authentication

API tokens are generated using HMAC-SHA256 with the SharedSecret and User-Agent. The token is calculated as:

```
API-Token = HMAC-SHA256(User-Agent, SharedSecret)
```

See the `validateAPIToken` function in the code for implementation details.

## Running Behind a Reverse Proxy

This proxy can run behind a reverse proxy like Nginx or Traefik. To properly configure it:

1. Set the `PUBLIC_URL` environment variable to the public-facing URL of your proxy
2. Ensure your reverse proxy forwards the `Host` header
3. Configure your reverse proxy to pass through any custom headers like `API-Token`

Example Nginx configuration:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name proxy.example.com;

    location / {
        proxy_pass http://complex-proxy:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

## Run in Coolify

This proxy works in Coolify with the following specific configuration:

1. Create a new service from Git repository
2. Set the Dockerfile path to `./Dockerfile`
3. Ensure the service has the `NET_ADMIN` capability enabled in Coolify's advanced settings
4. Set the appropriate environment variables in Coolify's UI:
   - `INTERFACE`: Set to the appropriate network interface in the container (usually `eth0`)
   - `IPV6_PREFIX`: Your IPv6 prefix
   - `IPV6_SUBNET`: Your IPv6 subnet
   - Other variables as needed for your setup
5. For IPv6 support, ensure your Coolify host has IPv6 connectivity

The docker-compose.yml file has been specifically modified to be compatible with Coolify's requirements, which doesn't support the `ipv6: true` network configuration that might be used in standard Docker environments.

> **Note**: If you're running this outside of Coolify and need IPv6 support, you'll need to configure Docker's IPv6 capabilities at the daemon level. See Docker's documentation on [enabling IPv6](https://docs.docker.com/config/daemon/ipv6/).

## Troubleshooting

- **IPv6 Issues**: Ensure your host has IPv6 properly configured and that Docker is configured to support IPv6 networking
- **Permission Issues**: The container requires CAP_NET_ADMIN to add IPv6 addresses
- **Connection Failures**: Check logs and verify the IPv6 prefix is correctly configured for your network

For more detailed logs, set DEBUG=true in your environment configuration.
