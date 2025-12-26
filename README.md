# CVE API

Go service that scans a directory of CVE JSON documents, builds a Bleve search index with a BoltDB backing store, and exposes a small HTTP API for listing and querying CVEs.

- Indexes CVE 5.x JSON files on startup and keeps the index in sync every 15 minutes.
- Serves lightweight endpoints for listing recent CVEs and searching by ID or free text.
- Separates search index storage from the raw data directory to avoid polluting the dataset.
- Includes an example CVE payload under `examples/` and tests for the indexing/sync loop.

## Quick start

1. Install Go 1.21+.
2. Point the service at a directory containing CVE JSON files (e.g., the `cvelistV5` repository) by editing `config.json` (see below).
3. Run the server:
   ```bash
   go run ./...
   ```
4. Test the service:
   ```bash
   go test ./...
   ```

## Configuration (`config.json`)

| Key         | Description |
|-------------|-------------|
| `ServerPort` | Port the HTTP server binds to (string, e.g., `"8080"`). |
| `EnableTLS`  | When `true`, the server starts with TLS using `CertFile` and `KeyFile`. |
| `CertFile`   | Path to the TLS certificate (required when TLS is enabled). |
| `KeyFile`    | Path to the TLS key (required when TLS is enabled). |
| `BasePath`   | Required. Directory that holds CVE JSON files to index. |
| `IndexPath`  | Where to store the Bleve index. Defaults to `.index` under `BasePath` if not set. If it matches `BasePath`, it is automatically moved to a hidden `.index` folder inside `BasePath`. |
| `StorePath`  | Path to the BoltDB file that stores the full CVE documents and file metadata. Defaults to `store.db` under `BasePath` when omitted. |
| `ignoreFiles | array of files to ignore, "somefile.txt"
| `AsyncIndex`| true/false, Allow web server to be reachable while initial indexing is ongoing. |

The repository includes a sample `config.json`. Adjust `BasePath` to your dataset before running.

```json
{
    "ServerPort": "8080",
    "EnableTLS": false,
    "CertFile": "/opt/fullchain.pem",
    "KeyFile": "/opt/privkey.pem",
    "BasePath": "examples/",
    "IndexPath": ".index",
    "StorePath": "store.db",
    "ignoreFiles": [
        "somefile.txt"
    ],
    "AsyncIndex": false
}
```

All endpoints use query parameters and return JSON.

- `GET /list` — Returns up to 50 most recent CVEs (ordered by `datePublished`).
- `GET /findID?search=<CVE-ID>` — Searches by CVE identifier. Falls back to scanning files if the index misses a match.
- `GET /findText?search=<query>` — Full-text search against the Bleve index; falls back to scanning files if the index yields no results.

## Data expectations

The indexer assumes CVE 5.x JSON structure. Files are read from `BasePath` recursively and any file with a `.json` extension is considered.

## Development notes

- Indexing and syncing run in a worker pool sized to available CPUs.
- The incremental sync loop re-indexes changed files and removes entries for deleted files.
- A single example CVE document is available at `examples/CVE-2024-58266.json` for quick smoke tests.
