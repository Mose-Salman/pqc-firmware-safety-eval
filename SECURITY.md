# Security policy

This repository contains synthetic defensive research cases. It does not contain production firmware or production secrets.

## Reporting a security issue

Avoid disclosing an exploitable issue in a third-party dependency or any real system in a public GitHub Issue. Report the problem to its maintainer using the responsible disclosure channel and provide only minimal non-sensitive reproduction information here.

For vulnerabilities in this research repository, open an issue that describes the affected component, reproducible conditions, and non-sensitive evidence. Do not post credentials, tokens, private keys, production data, or exploit material involving unauthorized systems.

## Operational guidance

- The CLI never requires credentials for dataset generation, validation, prompt previews, or result analysis.
- Live Claude calls are opt-in and incur API usage costs.
- The signing-key directory is temporary; no signing secret belongs in a public dataset.
- Verifier specimens are deliberately insecure in controlled variants. **Do not reuse them in production.**
- Only trusted, internally generated verifier templates are executed. Do not extend this to arbitrary externally supplied code without sandboxing.
- Treat benchmark labels as synthetic ground truth under the documented policy, not as evidence of any real vendor vulnerability.
