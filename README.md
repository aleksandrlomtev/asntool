# asntool

A command-line utility for retrieving ASN, owner, and associated CIDR prefixes (IPv4 and IPv6) for a given IP address, domain name, or ASN number. Powered by [ipapi.is](https://ipapi.is).

---

## Features

- **Flexible Input**: Supports IP addresses (IPv4 & IPv6), domain names, and ASN numbers (with or without `AS` prefix).
- **Comprehensive Output**: Returns ASN, owner information, and all associated CIDR prefixes.
- **Filtering Options**: Optionally filter results by address family (IPv4 or IPv6).
- **JSON Support**: Optionally output results in JSON format for easy machine processing.

---

## Installation

### Pre-built Binaries

Pre-compiled binaries for Windows, Linux, and macOS (supporting both amd64 and arm64 architectures) are available in the [Releases](https://github.com/aleksandrlomtev/asntool/releases) section.

### Build from Source

```bash
git clone https://github.com/aleksandrlomtev/asntool
cd asntool
go build -o asntool
```

### Requirements

- Go 1.16 or higher (for building from source)

---

## Usage

```bash
asntool <query> [flags]
```

### Query Formats

- **Domain name**: `asntool example.com`
- **IP address**: `asntool 8.8.8.8`
- **ASN number**: `asntool 15169` or `asntool AS15169`

### Optional Flags

- `-4`: Return only IPv4 prefixes.
- `-6`: Return only IPv6 prefixes.
- `-j`, `--json`: Output result in JSON format.

### Examples

```bash
asntool google.com
asntool 1.1.1.1 -4    # Get only IPv4 prefixes
asntool AS13335 -j    # Get output in JSON format
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/aleksandrlomtev/asntool).