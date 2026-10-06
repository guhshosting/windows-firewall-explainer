$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force artifacts,dist | Out-Null
& "$PSScriptRoot/build.ps1" -Analyze 2>&1 | Tee-Object artifacts/build.txt
ctest --test-dir build-release --output-on-failure 2>&1 | Tee-Object artifacts/ctest.txt
if($LASTEXITCODE) {throw 'Tests failed'}
& "$PSScriptRoot/static-analysis.ps1"
& 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\dumpbin.exe' /imports build-release/windows-firewall-explainer.exe | Set-Content artifacts/imports.txt
if($LASTEXITCODE) {throw 'Import inspection failed'}
cpack --config build-release/CPackConfig.cmake -B dist
if($LASTEXITCODE) {throw 'Packaging failed'}
Get-ChildItem dist -Filter '*.zip' | ForEach-Object {
 $hash=Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
 "$($hash.Hash.ToLower())  $($_.Name)" | Set-Content -LiteralPath ($_.FullName+'.sha256')
}
