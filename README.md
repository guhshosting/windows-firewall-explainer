# windows-firewall-explainer

> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


Version 1.0.0. A Windows-only C++17 CLI for explaining Windows Defender Firewall configuration. MIT licensed. No telemetry, intentional network access, probes, DNS, or firewall changes.

The application calls local COM getters on `INetFwPolicy2`, `INetFwRules`, `INetFwRule`, `INetFwRule2`, and `INetFwRule3`. It never invokes a shell, service-control mutation, firewall setter, or WFP filter mutation. `InetPtonW` parses numeric IP literals without creating a socket or initializing Winsock. COM/resources use RAII. Input and output use Unicode with UTF-8 output, including redirected output.

## Use

```text
windows-firewall-explainer --help
windows-firewall-explainer --version
windows-firewall-explainer status
windows-firewall-explainer rules --json
windows-firewall-explainer explain --direction inbound --protocol tcp --profile public --local-port 443 --remote-ip 192.0.2.10
windows-firewall-explainer explain --direction outbound --protocol udp --profile private --remote-port 53 --application "C:\Program Files\Example\example.exe" --json
```

`explain` requires direction, TCP/UDP protocol, and one explicit hypothetical profile. Other fields are optional; omitted fields are not wildcards and produce ambiguity for constrained rules. Ports are decimal 0–65535. IP inputs must be numeric IPv4 or IPv6 literals; hostnames, zone identifiers, and input subnets are rejected. Inspection does not open or inspect the supplied executable or contact the supplied address. Application paths require an absolute drive path. Service names identify a hypothetical Windows service; no service is started or queried.

Rule output includes names, descriptions, enabled state, direction/action, profile mask, protocol number, port/address lists, executable, service, interface types, grouping, edge traversal and extended package/security fields where accessible. Rules sort deterministically by their serialized fields. No rules is a valid empty array. A policy change during inspection can affect results because the snapshot is not atomic.

## Reading explanations

Each locally visible rule gets a category and reasons:

- `match`: the implemented tuple comparisons match. Unresolved interface bindings and runtime restrictions are still listed; this is not proof the rule applies to a packet.
- `excluded`: at least one known field contradicts the tuple, including disabled rules.
- `ambiguous`: no definite exclusion, but a supplied/omitted field, symbolic condition, extended security requirement, or getter failure prevents a complete configuration comparison.

Numeric rule ports, comma lists and inclusive ranges are supported. Symbolic ports such as RPC remain ambiguous. Numeric IPv4/IPv6 addresses, inclusive ranges, CIDR prefixes, and contiguous numeric netmasks are supported. Symbolic address tokens such as LocalSubnet, DNS or Internet remain ambiguous; the program never resolves them. An exact known match in a list suffices even if another element is symbolic. Executable and service names compare using Windows ordinal case-insensitive comparison; executable aliases, environment variables, slash differences, short names and file identity are not resolved. Interface selection is not an input and constrained interface types remain ambiguous. Unknown or absent API fields do not become unrestricted.

Profiles are Domain=1, Private=2, Public=4; combined masks use bit inclusion, and 2147483647 represents all. Status reports all three profiles and current profile mask, enabled state, default inbound/outbound actions, and block-all-inbound state. Explanation includes these defaults for context; it does not aggregate allow/block rules into a packet verdict. Profile disabled state or default allow policy does not establish that third-party filtering allows traffic.

## Scope and policy sources

This utility inspects the configuration exposed by the Windows Firewall automation interfaces. It does not enumerate the complete WFP engine, provider/callout filters, ALE runtime decisions, third-party products, connection state, dynamic rules outside the COM collection, IPsec negotiation, executable identity, service hardening or authenticated users. Edge traversal values are reported, not simulated. Rule visibility is not a guarantee of effective policy or local editability.

`LocalPolicyModifyState` exposes an aggregate condition for currently active profiles: 0=OK, 1=Group Policy override, 2=inbound blocked. Its HRESULT can indicate only some active profiles (`S_FALSE`); the output preserves that scope. It cannot establish an individual rule's provenance. Per-rule local/Group Policy source, editability, per-profile local-rule merging, excluded interfaces, and interface binding arrays are explicitly unavailable in this implementation. No access restriction is bypassed. These limitations, together with policy merging and runtime WFP arbitration, prevent authoritative allow/block claims.

Microsoft API references: [INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2), [LocalPolicyModifyState](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_localpolicymodifystate), [INetFwRule3](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule3).

## JSON and errors

`--json` works after every inspection command. Output is one JSON document on stdout. Schema version 1 has `version`, `mode`, `limitations`, `policy`, and `profiles`; rule modes add `rules`; explanations add `tuple` and `analysis`. Analysis indexes refer to the sorted `rules` array. Each configuration field is `{ "value": "...", "status": "value" }`. Values deliberately retain strings, including booleans, numeric protocol IDs and masks; consumers should parse these according to the field. Missing information is `{ "value": null, "status": "unavailable" }`, optionally with an HRESULT error. `empty`, `unrestricted`, `not_supplied`, `not_applicable`, and `unknown_value` are distinct statuses. Empty port/address strings remain ambiguous; empty application/service restrictions are unrestricted per their API semantics.

Exit codes: 0=completed inspection (individual unavailable getters remain explicit); 2=invalid command/input; 3=COM/policy/enumeration/internal failure. Failed enumerations never produce an apparently complete partial rule collection. JSON failures contain `schema_version`, `error`, and `exit_code`. Diagnostic text can include untrusted rule descriptions; use JSON for automation.

## Permissions and compatibility

Run as an ordinary user where Windows permits policy inspection. The executable has no elevation request or automatic retry. Access-denied getters remain unavailable; inaccessible policy/enumeration returns exit 3. Windows Defender Firewall components must be installed and accessible. The tool does not start disabled services.

Target: Windows 10, Windows 11, and supported Windows Server desktop API environments (Server 2016 and later). The code targets Windows 10 APIs, not Server 2025-specific APIs. The portable release is x64, statically linked to the MSVC runtime. ARM64/x86 builds are possible with corresponding toolchains but are not release-validated. Supported OS targets are design targets; see VALIDATION.md for actual tested coverage. No installer, background service or configuration files are required.

## Build, test and package

Use CMake 3.20+, an MSVC C++17 compiler, and a Windows SDK. From a Visual Studio developer terminal:

```text
cmake -S . -B build -A x64 -DWFE_ANALYZE=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cpack --config build/CPackConfig.cmake -C Release -B dist
```

`scripts/build.ps1` is a convenience script for the exact installed toolchain on the validation machine; the developer-terminal commands are portable between installations. Application safety restrictions apply to the shipped application; development scripts run compilers and validation tools only.

MSVC project code builds with `/W4 /WX`; `WFE_ANALYZE=ON` enables `/analyze`. A scoped suppression in the SDK includes avoids SDK `ws2tcpip.h` C6101 while leaving project analysis enabled. `WFE_CLANG_TIDY=ON` enables clang-tidy with warnings as errors and the checked-in configuration. Cppcheck: `cppcheck --enable=warning,performance,portability --error-exitcode=1 --std=c++17 --platform=win64 -Isrc src tests`. Clang-tidy may need Windows SDK/MSVC include paths in a developer environment. CTest includes unit comparisons, help/version, argument failures, live JSON inspection and a source safety scan. Live tests only read state and require accessible local firewall COM. The safety scan supplements manual API/import review; it is not a formal proof.

Release packaging uses CPack ZIP and includes the executable, README, license and validation report. No network connectivity is needed at runtime. The binary is unsigned; signing and publication are separate release-owner actions.
