# Sensitive File Finder for Websites

A security tool for discovering sensitive files on websites. Scans for multiple categories of sensitive files with customizable output formats.

## Features

- 🔍 Multiple scan categories:
  - Shell/backdoor files
  - Environment files
  - Git repository files
  - Other sensitive files
- 📊 Flexible output formats (JSON, CSV)
- 📁 Output file support
- 🎯 Category-based result tracking
- 🛡️ Soft-404 / false-positive filtering

## False-Positive Filtering

Many sites (SPAs, catch-all routers, custom error pages) return `200 OK` for
**any** path, including files that don't exist — e.g. `https://site/js/.env`
returns the SPA index page with status `200`. Without protection every probed
path looks like a "hit".

Before scanning, the tool probes several paths that should never exist and
records the signature (body size + `Content-Type`) of any `200` response. When
a real target file is found, its body is fetched and compared to those
baselines. If it matches (same content-type and body size within ~2%), it is
discarded as a false positive instead of being reported.

Baseline signatures are printed at the start of a scan when a soft-404 site is
detected.

## Installation

```bash
git clone https://github.com/begininvoke/SensitiveFileFuzzer.git
cd SensitiveFileFuzzer
go build
```

## Usage

Basic scan:
```bash
./SensitiveFileFuzzer -url https://example.com --shell
```

Comprehensive scan with JSON output:
```bash
./SensitiveFileFuzzer -url https://example.com --all -f json -o ./results
```

## Options

```bash
Usage of ./SensitiveFileFuzzer:
  -url string
        Target URL (e.g., https://example.com)
  -all
        Try all file lists
  -env
        Try environment file lists
  -git
        Try git-related file lists
  -sens
        Try sensitive file lists
  -shell
        Try shell/backdoor file lists
  -f string
        Output format: json or csv
  -o string
        Output directory path
  -v    
        Show only successful results
  -config string
        Custom config JSON file path
```

## Output Formats

### JSON Output
```json
{
  "total_count": 4,
  "categories": {
    "Git": [
      "https://example.com/.git/config",
      "https://example.com/.gitignore"
    ],
    "Environment": [
      "https://example.com/.env",
      "https://example.com/.env.local"
    ]
  },
  "summary": {
    "Git": 2,
    "Environment": 2
  }
}
```

### CSV Output
```csv
Category,URL
Git,https://example.com/.git/config
Git,https://example.com/.gitignore
Environment,https://example.com/.env
Environment,https://example.com/.env.local
```

### Console Output
```
🎯 Found 4 sensitive files:

📁 Git (2 files):
  └─ https://example.com/.git/config
  └─ https://example.com/.gitignore

📁 Environment (2 files):
  └─ https://example.com/.env
  └─ https://example.com/.env.local
```

## Configuration

Customize detection rules using a JSON configuration file:

```json
{
  "path": "/test.txt",
  "content": "#application/json#text/html",
  "length": "*"
}
```

### Content-Type Rules
- `"*"`: Accept any Content-Type
- `"#application/json#text/html"`: Exclude specific Content-Types
- `"application/json"`: Match exact Content-Type

### Content-Length Rules
- `"length": "10"`: Match responses with Content-Length >= 10
- `"length": "*"`: Accept any Content-Length

## Contributing

Pull requests are welcome. For major changes, please open an issue first.

## License

[MIT](https://choosealicense.com/licenses/mit/)