param([string]$BuildDirectory='build-release', [switch]$Analyze)
$ErrorActionPreference='Stop'
$vs='C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231'
$sdk='C:\Program Files (x86)\Windows Kits\10'
$env:PATH="$vs\bin\Hostx64\x64;$sdk\bin\10.0.26100.0\x64;"+$env:PATH
$env:INCLUDE="$vs\include;$sdk\Include\10.0.26100.0\ucrt;$sdk\Include\10.0.26100.0\shared;$sdk\Include\10.0.26100.0\um;$sdk\Include\10.0.26100.0\winrt"
$env:LIB="$vs\lib\x64;$sdk\Lib\10.0.26100.0\ucrt\x64;$sdk\Lib\10.0.26100.0\um\x64"
cmake -S . -B $BuildDirectory -G Ninja "-DCMAKE_MAKE_PROGRAM=C:/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe" "-DCMAKE_CXX_COMPILER=$vs/bin/Hostx64/x64/cl.exe" -DCMAKE_BUILD_TYPE=Release "-DWFE_ANALYZE=$($Analyze.IsPresent)"
if($LASTEXITCODE) { throw 'Configuration failed' }
cmake --build $BuildDirectory
if($LASTEXITCODE) { throw 'Build failed' }
