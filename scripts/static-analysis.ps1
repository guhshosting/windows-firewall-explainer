param([string]$BuildDirectory='build-release', [string[]]$Files=@('src/core.cpp','src/policy.cpp','src/main.cpp','tests/tests.cpp'))
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force artifacts/tidy | Out-Null
$db=Get-Content "$BuildDirectory/compile_commands.json" -Raw | ConvertFrom-Json
foreach($entry in $db) { $entry.command=$entry.command.Replace('/analyze ','') }
$db | ConvertTo-Json -Depth 10 | Set-Content artifacts/tidy/compile_commands.json
$includePaths=@(
 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\include',
 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt',
 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared',
 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um',
 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\winrt'
)
$extra=@($includePaths | ForEach-Object {"--extra-arg=/imsvc$_"})
& 'C:\Program Files\LLVM\bin\clang-tidy.exe' @Files -p artifacts/tidy @extra 2>&1 | Tee-Object artifacts/clang-tidy.txt
if($LASTEXITCODE) {throw 'clang-tidy failed'}
& 'C:\Program Files\Cppcheck\cppcheck.exe' --enable=warning,performance,portability --error-exitcode=1 --std=c++17 --platform=win64 --inline-suppr -Isrc src tests 2>&1 | Tee-Object artifacts/cppcheck.txt
if($LASTEXITCODE) {throw 'Cppcheck failed'}
