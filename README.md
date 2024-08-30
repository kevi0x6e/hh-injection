# hh-injection

hh-injection is a Go-based tool for testing and analyzing HTTP header injection vulnerabilities in specific URLs.

## Description

This tool allows you to check how a URL responds to different redirection attempts by manipulating the HTTP headers `Host`, `X-Host`, and `X-Forwarded-Host`. It is useful for identifying potential redirection vulnerabilities in web applications.

## Features

- Tests a URL with different combinations of HTTP headers
- Executes requests in parallel for improved efficiency
- Allows specifying the target URL and initial host via command line
- Displays the HTTP status code or redirection location for each attempt

## Requirements

- Go 1.13 or higher

## Installation

1. Clone the repository: 

```git clone https://github.com/kevi0x6e/hh-injection.git```

2. Navigate to the project directory:

```cd hh-injection```

3. Compile the program:

```go build -o hh-injection main.go```

## Usage

Run the program by specifying the URL and initial host:

Parameters:
- `-url`: The URL you want to test (default: "http://www.vulnerable.com")
- `-host`: The initial host to be used (default: "google.com")

## Examples

```

1. Test with default values:

./hh-injection

2. Test a specific website:

./hh-injection -url=http://www.mysiteone.com -host=mysitetwo.com

```

## Output

The tool will display the result of each attempt, showing whether there was a redirection or the HTTP status code received.

Example output:

Attempt 1: Status code: 200
Attempt 2: Redirected to: https://www.example.com/new-page
Attempt 3: Status code: 403

## Future Improvements

The following improvements are planned for future versions:

- [ ] Add Cookie Bomb attack
- [ ] Add Cache Poisoning attack
- [ ] Implementation of more robust concurrency
- [ ] Payload customization
- [ ] Implementation of evasion techniques
- [ ] Support for HTTP/2 and HTTP/3

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

This tool should be used for testing purposes only and with explicit permission. Misuse of this tool may violate terms of service or laws. Use at your own risk.
