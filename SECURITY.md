# Security Policy

## Supported Versions

The following table describes the current support policy for `threathunter-api`.

| Version | Supported |
|---------|-----------|
| Latest `main` branch | :white_check_mark: |
| Most recent release | :white_check_mark: |
| Older releases | :x: |

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately through one of these channels:

- GitHub Security Advisories, use the repository's **Report a vulnerability** feature.
- Email the maintainer or security contact listed for this repository.
- If a private security contact is not yet configured, open a minimal private outreach request through the repository owner profile and avoid including exploit details in public.

When submitting a report, include:

- A clear description of the issue.
- Affected endpoints, files, components, or dependency names.
- Steps to reproduce the behavior.
- Proof of concept, logs, screenshots, or sanitized request/response samples.
- Impact assessment, for example authentication bypass, data exposure, remote code execution, or denial of service.
- Suggested remediation, if available.

## Response Process

The project aims to follow this process:

- Acknowledge receipt within 3 business days.
- Provide an initial triage decision within 7 business days.
- Share status updates during remediation when a valid report requires longer investigation.
- Coordinate disclosure after a fix is available or mitigations are in place.

## Scope

This policy applies to:

- The API service and its source code.
- Authentication and authorization flows.
- CI/CD workflows, GitHub Actions, and dependency management.
- Infrastructure-as-code, container images, and deployment configuration when included in this repository.
- Documentation or examples that could create insecure defaults.

## Safe Harbor

Good-faith security research that avoids privacy violations, service disruption, and data destruction is welcomed.

Please:

- Avoid accessing, modifying, or deleting data that does not belong to you.
- Avoid denial-of-service, destructive testing, or automated abuse.
- Stop testing and report immediately if sensitive data is exposed.
- Give the project a reasonable amount of time to investigate and remediate before public disclosure.

## Security Practices

The repository may use the following practices as part of its security posture:

- Dependency monitoring and automated update review.
- Static analysis and vulnerability scanning in CI.
- Secret scanning and least-privilege token use.
- Container and supply-chain hygiene for build and release workflows.

## Disclosure

Public disclosure should occur only after maintainers confirm remediation or approve coordinated disclosure timing.
