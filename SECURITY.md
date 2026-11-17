# Security Disclosure

This document describes the security posture and vulnerability reporting
process for BoundaryGuard / AI Code Security Proxy.

**Last reviewed:** 2026-11  
**Scope:** This repository's NLIP gateway, secret-scanning proxy, policy
engine, demo UI, and evaluation tooling.

This disclosure is structured after the informative secure-by-design template
in ECMA-434 Annex A and reflects this project's actual demo configuration.

## ECMA-434 Profile 1 status

ECMA-434, *Security profiles for Natural Language Interaction Protocol*,
Profile 1 (clauses 7.1.1–7.1.3), covers transport confidentiality/integrity,
client authentication of the NLIP agent, and ethical-by-design lifecycle
disclosure. The repository documents its intended controls below, but the
default demo configuration is **not fully Profile 1 conformant**:

| Profile 1 area | Current implementation and deployment status |
|---|---|
| TLS with message integrity (7.1.1) | The documented local Uvicorn command uses plain HTTP on loopback. This repository does not configure TLS for the NLIP endpoint. A production deployment must provide TLS on client-to-agent and any agent-to-agent NLIP connections, including integrity protection. |
| Client authenticates the NLIP agent (7.1.2) | The demo does not configure an agent certificate or client-side identity verification. Deployments must use a trusted endpoint identity and ensure clients validate its certificate and hostname; do not disable certificate verification. |
| Ethical-by-design disclosure (7.1.3) | This repository publishes [ETHICS.md](ETHICS.md). It documents intended use, human control, privacy, fairness, and known limitations; it is not an independent ethical audit. |

Until TLS and agent identity verification are provided and checked in the
deployment environment, treat the demo as a local development example, not a
secure production NLIP endpoint. TLS termination at a trusted reverse proxy
can be used, but the proxy-to-agent hop must also be protected. The deployment
operator is responsible for certificate lifecycle, trust configuration, and
verifying that every relevant NLIP communication path is covered.

## Security disclosure information

| Field | Value |
|---|---|
| Claimant | BoundaryGuard project maintainers |
| Label scope | This repository and the components listed above |
| Claim date | 2026-11 |
| Security update status | Best effort; no guaranteed support period is currently published |
| Update method | Fixes are published through repository commits and, if issued, GitHub releases |
| Vulnerability disclosure policy | Use GitHub private vulnerability reporting if enabled; otherwise contact the maintainers privately through the repository. Do not post vulnerability details publicly before coordinating disclosure. |

## Secure development and deployment

- The project uses automated pytest coverage for policy behavior, detector
  obfuscation, gateway ingress/egress scanning, and evaluation metrics. Tests
  do not replace security review or penetration testing.
- Demo detector samples are synthetic. Do not commit production credentials,
  private keys, or sensitive evaluation data.
- The application logs detection metadata rather than secret values. Review
  host, reverse-proxy, analytics, and cloud-provider logs separately.
- The gateway's default mode is sanitize-only. Chat mode sends sanitized text
  to an external model provider. `allow`, `log`, allowlists, and detection
  misses can result in sensitive content being sent; validate policy and
  provider data-handling terms before use.
- Configure TLS and agent authentication outside the current local demo
  command. Use a current TLS configuration with message integrity, validate
  server certificates and hostnames at clients, and protect all gateway-to-
  agent hops.
- Keep policy files access-controlled. Regex allowlists can exempt broad
  values, while `allow` and `log` actions deliberately pass matches through.
- The scanner is heuristic: Unicode normalization, one layer of valid UTF-8
  Base64 decoding, regular expressions, and entropy checks improve coverage
  but do not guarantee that all secrets or sensitive information are detected.
- Non-text NLIP request parts are withheld by the gateway when they cannot be
  inspected. Verify the behavior of any adapters or deployment components
  added around the gateway.

## Reporting a vulnerability

Please report security issues privately. If GitHub private vulnerability
reporting is enabled for this repository, use the repository's **Security**
tab and **Report a vulnerability** option. Otherwise, contact the repository
maintainers privately through GitHub. Do not open a public issue containing
exploit details, credentials, private keys, or personal data.

Include, when safe to do so:

- affected commit, release, or deployment configuration;
- component and environment details;
- security impact and conditions required to reproduce;
- a minimal proof of concept using synthetic data; and
- any suggested mitigation.

Never include live secrets in the report. If a credential was exposed while
testing, revoke or rotate it immediately and report only its type and the
context of exposure. Maintainers will assess the report, coordinate a fix and
disclosure where practical, and publish security updates through the
repository.

## Known limitations

- No TLS listener or built-in agent identity verification is configured by the
  documented development commands.
- `POST /sanitize` enforces a `reject` policy with HTTP 422. Other scanning
  flows redact and report reject-policy findings; `allow` and `log` pass
  findings unchanged.
- The detector does not cover every secret format or every representation of
  sensitive information. Entropy heuristics can produce false positives.
- In chat mode, sanitized input is processed by an external model provider.
  Provider-side retention and processing are outside this project's control.
- The egress scan protects only responses that pass through this NLIP gateway;
  bypass paths and uninspected output formats are out of scope.

## Reference

ECMA International, [ECMA-434: Security profiles for Natural Language
Interaction Protocol (NLIP)](https://ecma-international.org/publications-and-standards/standards/ecma-434/),
1st edition, December 2025. This disclosure summarizes project status against
Profile 1 topics and is not a claim of independent certification.
