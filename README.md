# CVE API

Go service that scans a directory of CVE JSON documents, builds a Bleve search index with a BoltDB (bbolt) backing store, and exposes a small HTTP API for listing and querying CVEs.

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
| `StorePath`  | Path to the BoltDB (bbolt) file that stores the full CVE documents and file metadata. Defaults to `store.db` under `BasePath` when omitted. |
| `IgnoreFiles` | Array of filenames to ignore when scanning (optional). |
| `AsyncIndex` | `true`/`false`. When `true` the server starts immediately and the initial indexing runs in the background; when `false` indexing completes before the server becomes available. Defaults to `false`. |

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
    "IgnoreFiles": [
        "somefile.txt"
    ],
    "AsyncIndex": false
}
```

All endpoints use query parameters and return JSON.

- `GET /list` — Returns up to 50 most recent CVEs (ordered by `datePublished`).
- `GET /findID?search=<CVE-ID>` — Searches by CVE identifier. Returns results from the index/store.
- `GET /findText?search=<query>` — Full-text search against the Bleve index.
- `GET /index/fields` — Returns an array of the actual field names Bleve stores in the index (dotted, lower-cased paths).
- `GET /index/mappings` — Returns the Bleve index mapping as JSON (useful to inspect field types and stored settings).

Additional developer endpoints:
- `GET /openapi.json` — OpenAPI (Swagger) spec for the API.
- `GET /docs` — Interactive Swagger UI for the API.

Examples:

```bash
curl http://localhost:8080/index/fields        # list indexed field names
curl http://localhost:8080/index/mappings      # get mapping JSON
```

## Data expectations

The indexer assumes CVE 5.x JSON structure. Files are read from `BasePath` recursively and any file with a `.json` extension is considered.

Implementation notes:
- The project uses Bleve for full-text search and `go.etcd.io/bbolt` (bbolt) as the persistent store for full documents and file metadata.
- Bleve stores fields using dotted, lower-cased JSON paths (for example `cveMetadata.datePublished`) — if you need to inspect the index, the `bleve` CLI is helpful (`bleve check`, `bleve dump mapping`, `bleve query`).
- To apply mapping changes you must rebuild the Bleve index (delete the index directory and restart, or use the program's `Reindex` behavior if provided).

## Development notes

- Indexing and syncing run in a worker pool sized to available CPUs.
- The incremental sync loop re-indexes changed files and removes entries for deleted files.
- A single example CVE document is available at `examples/CVE-2024-58266.json` for quick smoke tests.
