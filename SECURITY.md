# Security

phplume is a local-network inventory tool. Its result labels describe evidence and uncertainty, not proven exploitability or a clean security state. See [the research notes](docs/research.md) for the reviewed advisories and boundaries.

Do not open a public issue containing credentials, internal network reports or an unpatched vulnerability. Report a vulnerability privately through this repository's GitHub security advisory reporting when available. For ordinary bugs, include a minimal synthetic reproduction and the tool/Python/OS version. Remove real hosts, addresses, cookies and application content.

The launcher and scanner execute with your current user's permissions. Run reviewed code from a trusted checkout or pinned release when that matters for your environment. No elevated privileges are required. A checksum in the launcher detects scanner mismatches; it does not authenticate the repository owner independently.

This initial release supports the dated CVE catalog bundled with it. It does not download rule updates, run in the background, change PHP settings or patch servers. Consult the upstream and vendor advisories before making remediation decisions.
