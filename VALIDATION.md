# Validation and release context: windows-firewall-explainer 1.0.0

Development/build validation: Windows Server 2025 x64. The exact executable completed physical Windows 11 Pro 25H2 x64 qualification (build 26200.9550) and Windows 10 Pro 22H2 x64 qualification in a dedicated QEMU VM (build 19045.6466). Physical Windows 10 hardware and ARM64 were not qualified. Windows 11 status: PASS, supported by the preserved physical qualification report dated 2026-10-02 and raw/run ledgers. Historical Windows 10 detailed ledgers are unavailable; completion is user supplied.

The final ZIP was assembled after executable qualification around the unchanged qualified EXE. Execution of this final assembled package on Windows is not claimed. Development validation is distinct from client qualification.

Qualified executable SHA-256: `3a66cf022e7fbffe306ab84addff6651c2536567c096cc530e574ccb3cf09229`.

No separately imported MSVC C++ runtime DLLs were found; Windows system libraries remain required.

Physical Windows 11 observations: Status, complete rule text/JSON, inbound TCP/443 explanations for domain/private/public, outbound UDP/53 human explanation, invalid port. Public active mask=4 agrees with Get-NetConnectionProfile Wi-Fi Public. Read-only NetSecurity profile/rule acquisition provides independent policy evidence; selected rule direction/action/enabled and TCP port/address constraints compared. No traffic sent; configured relevance never treated as packet verdict.

Recorded findings: No defect found. Current Public profile identified correctly. Explain output limits conclusions to configured-field relevance and preserves ambiguous/unavailable evidence.

Safety scope: local COM getters inspect configuration; no firewall mutation or traffic probes are requested. Configured-field relevance is not an effective packet allow/block verdict. Source/import review and sampled qualification observations do not prove packet-level silence or absence of all Windows internal activity.

Qualification safety limits: no broad filesystem, registry or policy mutation tracing was performed. Parent-PID TCP polling observed no connections; UDP, child traffic and packet-level activity were not monitored. These observations are not a formal proof of absence of all side effects.

See application documentation for query, output and safety limits. Windows may perform internal activity while servicing read-only API calls.
