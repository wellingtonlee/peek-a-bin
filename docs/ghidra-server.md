# Ghidra Decompilation Server

Optional companion server that provides high-quality decompilation via Ghidra's decompiler. Powers the **High Level** tab in the decompile panel.

## Overview

The server wraps Ghidra's decompiler via [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra) and exposes a REST API. Binaries are uploaded once and cached server-side by SHA-256 hash.

## Quick Start (Docker)

```bash
cd ghidra-server
docker build -t peek-a-bin-ghidra .
docker run --rm --name peek-a-bin-ghidra -p 8765:8765 peek-a-bin-ghidra
```

With API key authentication:

```bash
docker run -p 8765:8765 peek-a-bin-ghidra --api-key YOUR_SECRET
```

> **Platform note:** The Docker image is `linux/amd64` only. On Apple Silicon Macs, Docker Desktop uses Rosetta 2 for emulation automatically.

## Running Without Docker

Requires **Java 21+** and **Python 3.10+**:

```bash
cd ghidra-server
pip install -r requirements.txt
python server.py --port 8765
```

On first run, pyhidra will download and install Ghidra automatically.

To require authentication:

```bash
python server.py --port 8765 --api-key YOUR_SECRET
```

## Connecting from Peek-a-Bin

1. Open **Settings** in Peek-a-Bin (gear icon or command palette)
2. Go to the **Ghidra** tab
3. Check **Enable Ghidra server**
4. Enter the server URL (default: `http://localhost:8765`)
5. Enter the API key if the server was started with `--api-key`
6. Click **Test Connection** — on success, shows the server version and Ghidra version
7. Click **Save**

Once configured, the **High Level** tab in the decompile panel sends the binary to the Ghidra server and displays Ghidra's decompiled output.

## API Reference

### GET /api/v1/ping

Health check endpoint.

**Response:**
```json
{
  "version": "0.1.0",
  "ghidraVersion": "12.0.4"
}
```

### POST /api/v1/binary

Upload a PE binary for analysis. Multipart form data.

**Request:**
- `file`: Binary file (multipart upload)

**Response:**
```json
{
  "projectId": "a1b2c3d4e5f6..."
}
```

The `projectId` is the SHA-256 hash of the uploaded file. Subsequent uploads of the same file return the cached project ID.

### POST /api/v1/decompile

Decompile a function at a given address.

**Request body (JSON):**
```json
{
  "projectId": "a1b2c3d4e5f6...",
  "funcAddr": 4194304,
  "is64": true
}
```

**Response:**
```json
{
  "code": "void FUN_00401000(void) {\n  ...\n}",
  "lineMap": []
}
```

## Authentication

When the server is started with `--api-key`, all requests must include a Bearer token:

```
Authorization: Bearer YOUR_SECRET
```

Requests without a valid token receive a `401` or `403` response.

## Architecture

- **Caching:** Projects are cached by SHA-256 hash in `~/.peek-a-bin-server/projects/`. Uploading the same binary twice returns the existing project.
- **In-memory programs:** Ghidra `Program` objects are kept in memory for the duration of the server process. The dictionary maps `projectId` → `{ctx, flat_api, program}`.
- **CORS:** Allows all origins (`*`) for browser access.
- **Framework:** FastAPI with uvicorn, running on the specified port (default 8765).

## Troubleshooting

### Docker platform: linux/amd64 only

Ghidra's native decompiler binary (`decompile`) is only available for `linux_x86_64`. The Dockerfile forces `--platform=linux/amd64`. On Apple Silicon, Docker Desktop uses Rosetta 2 automatically.

If you see errors about missing architecture support, ensure Docker Desktop has Rosetta 2 emulation enabled (Settings > General > "Use Rosetta for x86_64/amd64 emulation on Apple Silicon").

### Ghidra 12 NotFoundException

Ghidra 12 throws `NotFoundException` (instead of `IOException`) when `openProject()` fails, which breaks pyhidra's fallback to `createProject()`. The server handles this automatically by catching `NotFoundException` and falling back to direct Java API calls (`GhidraProject.createProject` + `importProgram` + `analyze`).

### WindowsResourceReferenceAnalyzer NPE

Ghidra 12's `WindowsResourceReferenceAnalyzer` can crash with a `NullPointerException` due to uninitialized OSGi `BundleHost` when running via pyhidra outside of full Ghidra. The server automatically disables this analyzer in the fallback path. If analysis still fails, it's treated as non-fatal — the import continues without full analysis.

### DecompInterface.openProgram() returns false

This means the native decompiler binary is missing or not executable. The Docker image runs `chmod +x` on all native binaries during build. If running without Docker, ensure the Ghidra installation has executable permissions on files in `Ghidra/Features/*/os/linux_x86_64/`.

### CORS issues

The server allows all origins by default. If you're running behind a reverse proxy, ensure the proxy forwards CORS headers correctly, or configure the proxy's own CORS policy.

### Connection test fails

1. Verify the server is running: `curl http://localhost:8765/api/v1/ping`
2. Check the port matches what's configured in Peek-a-Bin settings
3. If using an API key, ensure it matches in both the server startup and Peek-a-Bin settings
4. Check browser console for network errors (mixed content if app is HTTPS but server is HTTP)
