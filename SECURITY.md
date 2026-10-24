# Security

Only version 0.1.x currently receives fixes. For suspected vulnerabilities, use
[GitHub private vulnerability reporting](https://github.com/KanadeK/cidr-witness/security/advisories/new).
If unavailable, open an issue requesting a private contact without publishing
the exploit or confidential data. Never attach secrets to a public issue.

This tool runs locally with the permissions of its caller. Treat inputs as
untrusted and use OS isolation when processing hostile data. Input and report
limits are documented in the README. A passing result covers only implemented
checks; it does not certify all downstream behavior.
