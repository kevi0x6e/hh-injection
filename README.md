# hh-injection

`hh-injection` is a Go-based tool designed to test and analyze HTTP header injection vulnerabilities on specific URLs.

## Description

This tool allows you to assess how a target URL responds to different manipulations of HTTP headers such as `Host`, `X-Host`, and `X-Forwarded-Host`, simulating header injection attacks, cache poisoning, and cookie bomb payloads. It is useful for identifying potential vulnerabilities like open redirects, host header injection, and related attack vectors.

## Requirements

- Go 1.13 or higher

## Installation

1. Clone the repository:

```bash
git clone https://github.com/kevi0x6e/hh-injection.git
```

2. Navigate to the project directory:

```bash
cd hh-injection
```

3. Build the binary:

```bash
go build -o hh-injection main.go
```

## Usage

Run the tool specifying the target URL and the host to inject:

### Parameters

- `-url` **(required)**: Target URL to be tested.
- `-test-host-injection` *(optional)*: Value to inject into the `Host` header and related headers.  
  **Default**: `google.com`
- `-cache-poison` *(optional)*: Enables the cache poisoning payload.
- `-cookie-bomb` *(optional)*: Enables the cookie bomb payload.

## Examples

```bash
# Basic test with default injected host (google.com)
./hh-injection -url https://victim-site.com

# Test with a custom injected host
./hh-injection -url https://victim-site.com -test-host-injection test.com

# Test with cache poisoning enabled
./hh-injection -url https://victim-site.com -test-host-injection test.com -cache-poison

# Test with cookie bomb enabled
./hh-injection -url https://victim-site.com -test-host-injection test.com -cookie-bomb

# Full test with cache poisoning and cookie bomb enabled
./hh-injection -url https://victim-site.com -test-host-injection test.com -cache-poison -cookie-bomb
```

## Future Improvements

- [ ] Payload customization
- [ ] Support for HTTP/2 and HTTP/3
- [ ] Support for authentication and custom cookies

## Contributing

Contributions are welcome! Please submit a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

This tool should be used only for authorized testing purposes. Unauthorized use may violate terms of service or laws. Use at your own risk.
