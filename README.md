# i6.shark - IPv6 Proxy Server

A configurable IPv6 proxy server for web scraping and testing.

## Features

- Dynamically manages IPv6 addresses to rotate through different IPs
- Supports HTTP/HTTPS requests with full request/response handling
- Handles Brotli and Gzip compression
- Configurable via environment variables
- Easy setup with pnpm scripts or Docker

## Requirements

### For direct installation:
- Go 1.21+
- Node.js and pnpm (for development scripts)
- Linux-based environment with IPv6 support
- Root privileges for binding to low ports and managing IPv6 addresses

### For Docker:
- Docker and Docker Compose
- Linux host with IPv6 connectivity

## Setup

### Option 1: Direct Installation

1. Clone the repository
2. Install dependencies:

```bash
pnpm install
```

This will attempt to install Air (Go hot-reloading tool) and set up all Go dependencies.

3. Configure your environment by editing the `.env` file

### Option 2: Docker

1. Clone the repository
2. Configure your environment by editing the `.env` file
3. Build and run with Docker Compose:

```bash
docker-compose up -d
```

## Running

### Development mode

Option 1 - using the dev script:
```bash
pnpm run dev
```

This will use Air for hot-reloading if available, or fall back to nodemon.

Option 2 - using the shell script (if Air can't be installed):
```bash
./dev.sh
```

### Production

#### Direct installation:
```bash
pnpm run build
sudo ./bin/i6shark
```

Or run directly:
```bash
sudo pnpm run start
```

#### Docker:
```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

## Configuration

All configuration is through environment variables. See `.env` file for all available options.

Key settings:

- `SHARED_SECRET`: API security token
- `IPV6_PREFIX`: Your IPv6 /48 prefix
- `IPV6_SUBNET`: Subnet within your /48
- `INTERFACE`: Network interface to use
- `LISTEN_PORT`: Server port (default 80)
- `DESIRED_POOL_SIZE`: Target number of IPv6 addresses to maintain

## API Usage

Make requests to the proxy with:

```
http://localhost/destination=https://target-site.com&headers={"custom-header":"value"}
```

Include the API-Token header calculated as:
```
HMAC-SHA256(User-Agent, SHARED_SECRET)
```

## Troubleshooting

### Air installation issues
If you encounter issues installing Air, you can:

1. Install it manually: `go install github.com/cosmtrek/air@latest`
2. Make sure your Go bin directory is in your PATH
3. Use the `./dev.sh` script as a fallback

### Go not found
If you see "go: command not found", make sure Go is installed and in your PATH.

### Docker networking issues
If you encounter problems with Docker networking:
- Ensure the host has IPv6 connectivity
- Make sure the Docker daemon is configured for IPv6
- Check that the interface name in `.env` matches the container's interface

## License

ISC
