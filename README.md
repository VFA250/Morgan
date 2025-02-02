# Morgan : Advanced JavaScript Security Analyzer
![Morgan](https://github.com/user-attachments/assets/0bcd0bbc-0974-48e0-a009-f5d1de779f6b)

Morgan is an advanced security tool designed to help developers, security professionals, and penetration testers identify and analyze sensitive data exposed within JavaScript files embedded in websites. It provides an automated solution for detecting API keys, authentication tokens, access credentials, private keys, and other sensitive information that may be unintentionally exposed within client-side JavaScript.

In modern web applications, JavaScript files often contain not only functionality but also configuration data, sensitive credentials, and keys that can be exploited if leaked. Morgan analyzes JavaScript files to uncover these hidden security risks, ensuring that websites or web applications don’t inadvertently expose sensitive data to unauthorized users. The tool performs in-depth scanning by examining the content of JavaScript files using pattern matching, entropy analysis, and obfuscation detection.

## Key Features
### Pattern-Based Detection
Morgan employs a wide range of predefined regular expression patterns to detect sensitive data embedded in JavaScript files. This includes but is not limited to,

- API Keys & Tokens: Detects common patterns for API keys, OAuth tokens, database connection strings, and cloud provider credentials (e.g., AWS, GitHub, Slack, Stripe).
- Private Keys: Detects various types of private keys, including SSH, RSA, and EC private keys.
- Credentials: Identifies potential passwords, usernames, session IDs, and other forms of sensitive credentials.
- URLs & IP Addresses: Finds URLs and IP addresses that might indicate sensitive endpoints or internal resources exposed unintentionally.

These patterns are customizable, allowing the user to add or modify regex patterns to suit specific use cases or identify proprietary sensitive data formats.

### Entropy-Based Detection
In addition to predefined patterns, Morgan also performs entropy analysis to detect high-entropy strings that might indicate randomly generated tokens or secrets. Entropy refers to the amount of randomness or unpredictability in a string, and high-entropy strings are typically used for secure tokens, passwords, and keys. This is a powerful technique for finding obfuscated or poorly protected sensitive information that may not match traditional patterns.

### Obfuscation Detection
Morgan includes several built-in indicators to detect obfuscation techniques often used to hide sensitive information in JavaScript. Obfuscation is commonly used to make JavaScript harder to analyze or reverse engineer, but it can also serve to hide sensitive data from casual inspection. Morgan looks for common obfuscation patterns such as,

- Use of eval(), Function(), and other dynamic execution functions.
- Base64 Encoding/Decoding: Detects atob() and btoa() functions used for encoding/decoding data.
- Hexadecimal Encoding: Detects string patterns encoded using hexadecimal representation.
- String Concatenation: Detects unusual patterns of string concatenation used to obfuscate meaningful strings.

These techniques enable Morgan to identify potentially hidden secrets that are encoded or obfuscated within the JavaScript code.

<img width="1710" alt="2" src="https://github.com/user-attachments/assets/bbbaed25-d5fc-4de0-b676-414397df0182" />

### Content Security Policy (CSP) Analysis
Morgan can also fetch and analyze a website’s Content Security Policy (CSP) header. CSP is a browser security feature that helps prevent cross-site scripting (XSS) attacks and other content injection attacks. Morgan checks for weak or misconfigured CSPs, such as,
- Usage of unsafe-inline: Allows the execution of inline JavaScript, which can be a vector for XSS attacks.
- Usage of unsafe-eval: Enables the use of eval(), which is often abused by malicious scripts to execute arbitrary code.

By analyzing the CSP header, Morgan helps ensure that the website is following best practices for content security.

### JavaScript File Extraction & Download
Morgan is capable of crawling a webpage to extract embedded JavaScript files and analyze them for sensitive data. The tool downloads JavaScript files, parses them, and then checks them for potential leaks. Additionally, if a user specifies the --download flag, Morgan can save the raw JavaScript files locally for further inspection or offline analysis.

### Caching for Performance Optimization
Morgan uses an intelligent caching mechanism to improve performance and avoid redundant analysis. When a website is scanned, the tool caches the results of the scan, including the list of JavaScript files and findings, in a local directory. This allows future scans of the same site to load the cached results, significantly speeding up the process and reducing unnecessary network requests.

### Multi-Threaded & Parallel Processing
To handle large numbers of JavaScript files or websites efficiently, Morgan makes use of concurrent threading using Python’s ThreadPoolExecutor. This enables the tool to scan multiple JavaScript files in parallel, dramatically improving scanning speed. It also supports parallel downloading of JavaScript files if the --download flag is enabled.

### Customizable Scans
Morgan allows users to perform highly customizable scans with the following options,

- Timeout Settings: You can configure the --timeout option to control the time allowed for fetching resources from a website.
- Depth of Scan: The --depth option controls how deeply Morgan crawls into nested URLs and resources.
- Filters: The --filter flag enables filtering of specific patterns (e.g., only show API keys or JWT tokens) in the scan results.
- User-Agent Customization: Morgan allows the use of custom user-agent strings via the --user-agent-file option. This is particularly useful when scanning websites that may block or throttle requests based on user-agent headers.

<img width="1710" alt="1" src="https://github.com/user-attachments/assets/830df44b-2b51-4cd4-9aee-5a8a4c2f85f0" />

## Usage
Morgan is designed to be run from the command line, providing a straightforward interface for initiating scans. A user can scan a single website or a list of URLs and configure various options to tailor the scan to their needs. The tool provides detailed results, listing any sensitive information detected along with the corresponding JavaScript file or URL where the data was found.

Here is an example of a typical usage scenario,

```python
python Morgan.py https://example.com --download --timeout 10 --filter "API Key" --entropy 5
```

This command will,

1. Scan https://example.com.
2. Download any JavaScript files found.
3. Set a timeout of 10 seconds for each request.
4. Filter the results to only show “API Key” findings.
5. Set an entropy threshold of 5 to detect high-entropy strings.

## Advanced Configuration
In addition to standard usage, Morgan also supports advanced configuration for custom use cases. Users can provide a file of URLs to be scanned or pass a list of user-agent strings to mimic requests from different browsers or devices.

## Future Enhancements
Morgan is designed to be modular, allowing the community to contribute and extend its functionality. Potential future improvements include,

- Support for Additional Obfuscation Detection: Expanding the range of obfuscation techniques detected, such as more advanced packing or minification methods.
- Extended Pattern Library: Enabling users to easily integrate custom patterns for their specific use cases or industry-specific secrets.
- GUI Interface: A graphical user interface (GUI) to provide a more user-friendly experience for less technical users.

## Conclusion
Morgan is a versatile, high-performance tool aimed at enhancing the security of web applications by automating the detection of sensitive data in JavaScript files. With its robust feature set, it provides developers, security professionals, and auditors with an efficient way to identify and mitigate security risks associated with exposed credentials and misconfigurations. Through its intelligent caching, parallel processing, and customizable options, Morgan provides a thorough and flexible solution for securing modern web applications.
