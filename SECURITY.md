# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in
`x25519_adekvat`, please do not disclose it publicly through GitHub Issues,
pull requests, or other public channels.

Security vulnerabilities should be reported privately through
[GitHub Security Advisories](https://github.com/kostya2023/x25519_adekvat/security/advisories).

If possible, please include:

- A description of the vulnerability.
- The affected version or commit.
- Steps to reproduce the issue.
- The potential security impact.
- Any relevant test cases or proof of concept.
- Suggested mitigation or fix, if available.

## Supported Versions

`x25519_adekvat` is currently in beta.

| Version | Supported |
|---------|-----------|
| 1.0.0-beta.1 | Yes |
| 0.x | No |

Security fixes will normally be released as a new version when
appropriate.

## Security Audits

`x25519_adekvat` has not yet undergone an independent security audit.

The project has undergone maintainer-performed security testing,
including:

- RFC 7748 test vectors.
- RFC 7748 1000-iteration test.
- Diffie-Hellman symmetry tests.
- `dudect` timing analysis.
- Manual inspection of generated optimized assembly.
- Review of secret-dependent control flow and memory access.
- Verification of the fixed 255-iteration Montgomery ladder.
- Verification that the X25519 ladder does not use precomputed lookup
  tables.

These checks do not constitute a formal security audit or a proof of
constant-time execution.

The project will remain in beta until an independent security review can
be performed. The goal is to address any findings from such a review
before the `1.0.0` stable release.

## Disclosure

Security vulnerabilities will be investigated and fixed as appropriate.

For vulnerabilities that could affect users, coordinated disclosure is
preferred. Public disclosure may be made after a fix or mitigation is
available.

## Security-Sensitive Changes

Changes affecting the following areas are considered security-sensitive:

- Field arithmetic.
- Scalar processing and clamping.
- Montgomery ladder implementation.
- Encoding and decoding.
- Constant-time behavior.
- Secret-dependent control flow or memory access.
- Private-key handling and zeroization.
- Cryptographic API design.

Such changes should receive additional testing and review before release.

## Scope

This security policy applies to the `x25519_adekvat` source code and its
official releases.

Applications and protocols built using `x25519_adekvat` are outside the
scope of this project. In particular, `x25519_adekvat` provides key
agreement but does not provide authentication, encryption, key
derivation, or protocol-level security.

Users are responsible for using X25519 as part of an appropriate
cryptographic protocol.