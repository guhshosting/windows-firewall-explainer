param([Parameter(Mandatory)][string]$Root)
$ErrorActionPreference='Stop'
$source=(Get-ChildItem -LiteralPath "$Root/src" -File | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw}) -join "`n"
$forbidden='\bput_\w+\s*\(|\b(socket|WSASocket\w*|connect|send\w*|recv\w*|getaddrinfo|GetAddrInfo\w*|DnsQuery\w*|WinHttp\w*|InternetOpen\w*|CreateProcess\w*|ShellExecute\w*|system|_wsystem|popen|_popen|StartService\w*|ControlService|ChangeServiceConfig\w*|FwpmFilterAdd\w*|FwpmFilterDelete\w*|Remove|Add)\s*\('
if($source -match $forbidden) {throw "Forbidden API found: $($Matches[0])"}
if($source -match '(?i)netsh|powershell|cmd\.exe') {throw 'Shell reference in application source'}
Write-Output 'Application source safety scan passed (supplements manual API review)'
