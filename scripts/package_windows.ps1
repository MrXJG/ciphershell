param(
  [string]$BuildDir,
  [string]$Configuration = "Release",
  [switch]$SkipTests,
  [switch]$RequireFullEngineBundle,
  [switch]$RequireWebTerminalBundle = $true,
  [ValidateSet("auto", "msys2", "msvc")]
  [string]$Toolchain = "auto",
  [string]$QtRoot,
  [string]$OpenSslRoot,
  [string]$MsysRoot = "C:\msys64",
  [string]$VsDevCmd
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
  $BuildDir = Join-Path $RootDir "build-win"
}
$BuildDir = [System.IO.Path]::GetFullPath($BuildDir)
$PackageDir = Join-Path $BuildDir "package"
$StageDir = Join-Path $PackageDir "ciphershell"
$ReportDir = Join-Path $BuildDir ("package-verification\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
$PortableZip = Join-Path $BuildDir "ciphershell-0.1.1-win64-portable.zip"
$InstallerExe = Join-Path $BuildDir "ciphershell-0.1.1-win64-setup.exe"
$ReportPath = Join-Path $ReportDir "package-report.json"
$PackageTestReportPath = Join-Path $ReportDir "windows-package-test-report.json"
$UcrtBinDir = Join-Path $MsysRoot "ucrt64\bin"
$UsrBinDir = Join-Path $MsysRoot "usr\bin"
$Bash = Join-Path $UsrBinDir "bash.exe"
$MakeNsis = Join-Path $UcrtBinDir "makensis.exe"
$Objdump = Join-Path $UcrtBinDir "objdump.exe"

function Copy-RequiredDlls([string]$SourceDir, [string]$DestinationDir, [string[]]$DllNames) {
  New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null
  foreach ($Dll in $DllNames) {
    $SourceDll = Join-Path $SourceDir $Dll
    if (!(Test-Path $SourceDll)) {
      throw "Required runtime DLL not found: $SourceDll"
    }
    Copy-Item -Force $SourceDll $DestinationDir
  }
}

function Copy-ExistingDlls([string[]]$SourceDirs, [string]$DestinationDir, [string[]]$DllNames) {
  New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null
  $copied = @()
  foreach ($dll in $DllNames) {
    $source = Find-DllSource $dll $SourceDirs
    if ($source) {
      Copy-Item -Force $source $DestinationDir
      $copied += $dll
    }
  }
  return $copied | Select-Object -Unique
}

function Get-ImportedDlls([string]$Path) {
  $lines = & $Objdump -p $Path 2>$null | Select-String "DLL Name:"
  $dlls = @()
  foreach ($line in $lines) {
    $dlls += (($line.Line -replace '^\s*DLL Name:\s*', '').Trim())
  }
  return $dlls | Where-Object { $_ } | Select-Object -Unique
}

function Test-SystemDllName([string]$DllName) {
  $lower = $DllName.ToLowerInvariant()
  if ($lower -like "api-ms-*" -or $lower -like "ext-ms-*") {
    return $true
  }
  $systemDlls = @(
    "advapi32.dll", "authz.dll", "bcrypt.dll", "cfgmgr32.dll",
    "comctl32.dll", "comdlg32.dll", "crypt32.dll", "cryptsp.dll",
    "d3d9.dll", "d3d11.dll", "d3d12.dll", "dcomp.dll", "dnsapi.dll",
    "dwmapi.dll", "dwrite.dll", "dxgi.dll", "gdi32.dll",
    "glu32.dll", "imm32.dll", "iphlpapi.dll", "kernel32.dll",
    "mpr.dll", "msvcrt.dll", "ncrypt.dll", "netapi32.dll", "ntdll.dll", "ole32.dll",
    "oleacc.dll", "oleaut32.dll", "opengl32.dll", "powrprof.dll",
    "propsys.dll", "rpcrt4.dll", "secur32.dll", "setupapi.dll",
    "shcore.dll", "shell32.dll", "shlwapi.dll", "ucrtbase.dll",
    "user32.dll", "userenv.dll", "usp10.dll", "uxtheme.dll",
    "version.dll", "winhttp.dll", "winmm.dll",
    "winspool.drv", "ws2_32.dll", "wtsapi32.dll"
  )
  return $systemDlls -contains $lower
}

function Test-DllInDirs([string]$DllName, [string[]]$Dirs) {
  foreach ($Dir in ($Dirs | Where-Object { $_ } | Select-Object -Unique)) {
    if (Test-Path (Join-Path $Dir $DllName)) {
      return $true
    }
  }
  return $false
}

function Find-DllSource([string]$DllName, [string[]]$SourceDirs) {
  foreach ($Dir in $SourceDirs) {
    if (!$Dir) {
      continue
    }
    $Candidate = Join-Path $Dir $DllName
    if (Test-Path $Candidate) {
      return $Candidate
    }
  }
  return $null
}

function Get-PeFiles([string]$Root, [string[]]$ExcludeRoots) {
  $normalizedExcludes = @()
  foreach ($Exclude in $ExcludeRoots) {
    if ($Exclude -and (Test-Path $Exclude)) {
      $normalizedExcludes += [System.IO.Path]::GetFullPath($Exclude).TrimEnd('\')
    }
  }
  Get-ChildItem -Recurse -File -Path $Root |
    Where-Object {
      if ($_.Extension.ToLowerInvariant() -notin @(".exe", ".dll")) {
        return $false
      }
      $full = [System.IO.Path]::GetFullPath($_.FullName)
      foreach ($Exclude in $normalizedExcludes) {
        if ($full.StartsWith($Exclude, [System.StringComparison]::OrdinalIgnoreCase)) {
          return $false
        }
      }
      return $true
    }
}

function Copy-ResolvedRuntimeDllClosure(
  [string]$Root,
  [string]$DestinationDir,
  [string[]]$SourceDirs,
  [string[]]$ExcludeRoots,
  [string]$Label
) {
  New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null
  $Copied = [ordered]@{}
  for ($i = 0; $i -lt 30; ++$i) {
    $changed = $false
    $missing = @()
    foreach ($pe in (Get-PeFiles $Root $ExcludeRoots)) {
      $peDir = Split-Path -Parent $pe.FullName
      foreach ($dll in (Get-ImportedDlls $pe.FullName)) {
        if (Test-SystemDllName $dll) {
          continue
        }
        if (Test-DllInDirs $dll @($DestinationDir, $peDir)) {
          continue
        }
        $source = Find-DllSource $dll $SourceDirs
        if ($source) {
          Copy-Item -Force $source $DestinationDir
          $Copied[$dll] = [ordered]@{
            source = $source
            destination = (Join-Path $DestinationDir $dll)
          }
          $changed = $true
        } else {
          $missing += "$($pe.FullName) -> $dll"
        }
      }
    }
    if (!$changed) {
      if ($missing.Count -gt 0) {
        throw "$Label runtime dependency resolution failed: $($missing -join '; ')"
      }
      return $Copied
    }
  }
  throw "$Label runtime dependency resolution exceeded iteration limit"
}

function Find-QtMsvcRoot([string]$Preferred) {
  if ($Preferred) {
    $candidate = [System.IO.Path]::GetFullPath($Preferred)
    if (Test-Path (Join-Path $candidate "bin\windeployqt.exe")) {
      return $candidate
    }
    throw "QtRoot does not contain bin\\windeployqt.exe: $candidate"
  }

  $candidates = @()
  if ($env:GMSSH_QT_ROOT) {
    $candidates += $env:GMSSH_QT_ROOT
  }
  $candidates += @(
    "C:\Users\gmssh-build\Qt\6.10.3\msvc2022_64",
    "C:\Qt\6.10.3\msvc2022_64",
    "C:\Qt\6.9.0\msvc2022_64"
  )
  foreach ($c in $candidates | Where-Object { $_ } | Select-Object -Unique) {
    if (Test-Path (Join-Path $c "bin\windeployqt.exe")) {
      return [System.IO.Path]::GetFullPath($c)
    }
  }
  return $null
}

function Find-VsDevCmd([string]$Preferred) {
  if ($Preferred) {
    $resolved = [System.IO.Path]::GetFullPath($Preferred)
    if (!(Test-Path $resolved)) {
      throw "VsDevCmd not found: $resolved"
    }
    return $resolved
  }
  if ($env:VSDEVCMD_PATH -and (Test-Path $env:VSDEVCMD_PATH)) {
    return [System.IO.Path]::GetFullPath($env:VSDEVCMD_PATH)
  }
  $known = @(
    "C:\BuildTools\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
  )
  foreach ($path in $known) {
    if (Test-Path $path) {
      return $path
    }
  }
  return $null
}

function Find-OpenSslRoot([string]$Preferred) {
  $candidates = @()
  if ($Preferred) {
    $candidates += $Preferred
  }
  if ($env:GMSSH_OPENSSL_ROOT) {
    $candidates += $env:GMSSH_OPENSSL_ROOT
  }
  $candidates += @(
    "C:\Users\gmssh-build\Qt\Tools\OpenSSLv3\Win_x64",
    "C:\Qt\Tools\OpenSSLv3\Win_x64"
  )
  foreach ($c in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
    $root = [System.IO.Path]::GetFullPath($c)
    $lib = Join-Path $root "lib\libcrypto.lib"
    $inc = Join-Path $root "include\openssl\evp.h"
    if ((Test-Path $lib) -and (Test-Path $inc)) {
      return $root
    }
  }
  return $null
}

function Get-MsvcRuntimeSourceDirs([string]$VsDevCmdPath) {
  $dirs = @()
  if ($VsDevCmdPath) {
    $buildToolsRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $VsDevCmdPath))
    $redistRoot = Join-Path $buildToolsRoot "VC\Redist\MSVC"
    if (Test-Path $redistRoot) {
      $redistBins = Get-ChildItem -Path $redistRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName "x64\Microsoft.VC143.CRT" }
      foreach ($rb in $redistBins) {
        if (Test-Path $rb) {
          $dirs += $rb
        }
      }
    }
  }
  $dirs += [Environment]::SystemDirectory
  return $dirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
}

function Get-WindowsKitBinDirs() {
  $roots = @()
  $base = "C:\Program Files (x86)\Windows Kits\10\bin"
  if (Test-Path $base) {
    $roots += Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue |
      Sort-Object Name -Descending |
      ForEach-Object { Join-Path $_.FullName "x64" }
  }
  return $roots | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
}

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

$QtMsvcRoot = Find-QtMsvcRoot $QtRoot
$ResolvedVsDevCmd = Find-VsDevCmd $VsDevCmd
$ResolvedOpenSslRoot = Find-OpenSslRoot $OpenSslRoot
$SelectedToolchain = $Toolchain
if ($SelectedToolchain -eq "auto") {
  if ($QtMsvcRoot -and $ResolvedVsDevCmd) {
    $SelectedToolchain = "msvc"
  } else {
    $SelectedToolchain = "msys2"
  }
}

if ($SelectedToolchain -eq "msvc") {
  if (!$QtMsvcRoot) {
    throw "MSVC toolchain selected but no official Qt root with WebEngine found. Set -QtRoot."
  }
  if (!$ResolvedVsDevCmd) {
    throw "MSVC toolchain selected but VsDevCmd.bat not found. Set -VsDevCmd or install Visual Studio Build Tools."
  }
  if (!$ResolvedOpenSslRoot) {
    throw "MSVC toolchain selected but OpenSSL development root not found. Set -OpenSslRoot or install tools_opensslv3_x64."
  }
}

$WinDeployQt = if ($SelectedToolchain -eq "msvc") {
  Join-Path $QtMsvcRoot "bin\windeployqt.exe"
} else {
  Join-Path $UcrtBinDir "windeployqt.exe"
}

foreach ($Required in @($MakeNsis, $Objdump, $WinDeployQt)) {
  if (!(Test-Path $Required)) {
    throw "Required tool not found: $Required"
  }
}
if ($SelectedToolchain -eq "msys2" -and !(Test-Path $Bash)) {
  throw "Required tool not found: $Bash"
}

function Convert-ToMsysPath([string]$Path) {
  $Full = [System.IO.Path]::GetFullPath($Path).Replace('\', '/')
  if ($Full -match '^([A-Za-z]):/(.*)$') {
    return ('/' + $Matches[1].ToLowerInvariant() + '/' + $Matches[2])
  }
  return $Full
}

$RootMsys = Convert-ToMsysPath $RootDir
$BuildMsys = Convert-ToMsysPath $BuildDir
$TestArg = if ($SkipTests) { "" } else { "ctest --test-dir '$BuildMsys' --output-on-failure" }
$BuildLogPath = Join-Path $ReportDir "build-and-test.log"
$NativeErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$BuildExitCode = 0
if ($SelectedToolchain -eq "msys2") {
  $BuildScript = @"
set -euo pipefail
export MSYSTEM=UCRT64
export PATH=/ucrt64/bin:/usr/bin:`$PATH
cmake -S '$RootMsys' -B '$BuildMsys' -G Ninja -DCMAKE_BUILD_TYPE='$Configuration' -DGMSSH_ENABLE_WEB_TERMINAL=ON -DGMSSH_REQUIRE_WEB_TERMINAL=ON
cmake --build '$BuildMsys' --parallel `$(nproc)
$TestArg
"@
  & $Bash -lc $BuildScript 2>&1 | Tee-Object -FilePath $BuildLogPath
  $BuildExitCode = $LASTEXITCODE
} else {
  $BuildCmdPath = Join-Path $ReportDir "build-msvc.cmd"
  $QtPrefix = $QtMsvcRoot.Replace('"', '""')
  $QtBin = (Join-Path $QtMsvcRoot "bin").Replace('"', '""')
  $OpenSslPrefix = $ResolvedOpenSslRoot.Replace('"', '""')
  $OpenSslInclude = (Join-Path $ResolvedOpenSslRoot "include").Replace('"', '""')
  $OpenSslBin = (Join-Path $ResolvedOpenSslRoot "bin").Replace('"', '""')
  $OpenSslCryptoLib = (Join-Path $ResolvedOpenSslRoot "lib\libcrypto.lib").Replace('"', '""')
  $OpenSslSslLib = (Join-Path $ResolvedOpenSslRoot "lib\libssl.lib").Replace('"', '""')
  $VsDevCmdEscaped = $ResolvedVsDevCmd.Replace('"', '""')
  $RootEscaped = $RootDir.Replace('"', '""')
  $BuildEscaped = $BuildDir.Replace('"', '""')
  $MsvcTestStep = if ($SkipTests) {
    "echo [skip] tests"
  } else {
    "set `"PATH=$QtBin;$OpenSslBin;%PATH%`"`r`nctest --test-dir `"$BuildEscaped`" -C $Configuration --output-on-failure`r`nif errorlevel 1 exit /b 1"
  }
  @"
@echo off
call "$VsDevCmdEscaped" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1
where cmake >nul 2>nul
if errorlevel 1 exit /b 1
where ninja >nul 2>nul
if errorlevel 1 exit /b 1
if exist "$BuildEscaped\CMakeCache.txt" del /f /q "$BuildEscaped\CMakeCache.txt"
if exist "$BuildEscaped\CMakeFiles" rmdir /s /q "$BuildEscaped\CMakeFiles"
cmake -S "$RootEscaped" -B "$BuildEscaped" -G Ninja -DCMAKE_BUILD_TYPE=$Configuration -DCMAKE_PREFIX_PATH="$QtPrefix" -DOPENSSL_ROOT_DIR="$OpenSslPrefix" -DOPENSSL_INCLUDE_DIR="$OpenSslInclude" -DOPENSSL_CRYPTO_LIBRARY="$OpenSslCryptoLib" -DOPENSSL_SSL_LIBRARY="$OpenSslSslLib" -DGMSSH_ENABLE_WEB_TERMINAL=ON -DGMSSH_REQUIRE_WEB_TERMINAL=ON
if errorlevel 1 exit /b 1
cmake --build "$BuildEscaped" --parallel
if errorlevel 1 exit /b 1
$MsvcTestStep
"@ | Set-Content -Encoding ASCII -Path $BuildCmdPath
  & cmd.exe /d /c $BuildCmdPath 2>&1 | Tee-Object -FilePath $BuildLogPath
  $BuildExitCode = $LASTEXITCODE
}
$ErrorActionPreference = $NativeErrorAction
if ($BuildExitCode -ne 0) {
  throw "Build/test failed; see $BuildLogPath"
}
$BuildLogContent = Get-Content -Raw -Path $BuildLogPath
$TerminalRenderer = "unknown"
if ($BuildLogContent -match "Embedded web terminal enabled \(Qt WebEngine \+ WebChannel\)\.") {
  $TerminalRenderer = "webengine"
} elseif ($BuildLogContent -match "falling back to legacy terminal renderer") {
  $TerminalRenderer = "legacy"
}
if ($BuildLogContent -match "falling back to legacy terminal renderer") {
  throw "Build produced a legacy-terminal fallback, but Windows packaging requires embedded web terminal."
}
if ($BuildLogContent -notmatch "Embedded web terminal enabled \(Qt WebEngine \+ WebChannel\)\.") {
  throw "Build did not confirm embedded web terminal enablement; check WebEngine/WebChannel toolchain."
}

$AppExe = Join-Path $BuildDir "CipherShell.exe"
if (!(Test-Path $AppExe) -and $SelectedToolchain -eq "msvc") {
  $candidate = Join-Path $BuildDir $Configuration
  $candidate = Join-Path $candidate "CipherShell.exe"
  if (Test-Path $candidate) {
    $AppExe = $candidate
  }
}
if (!(Test-Path $AppExe)) {
  throw "Built executable not found: $AppExe"
}

Remove-Item -Recurse -Force $StageDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
Copy-Item -Force $AppExe $StageDir

$BuiltBinDir = Join-Path $BuildDir "bin"
if (Test-Path $BuiltBinDir) {
  Copy-Item -Recurse -Force $BuiltBinDir (Join-Path $StageDir "bin")
}

$StageEngineDir = Join-Path $StageDir "bin"
if (Test-Path $StageEngineDir) {
  foreach ($Dll in @("msys-2.0.dll", "msys-crypto-3.dll", "msys-z.dll", "msys-gcc_s-seh-1.dll")) {
    $SourceDll = Join-Path $UsrBinDir $Dll
    if (Test-Path $SourceDll) {
      Copy-Item -Force $SourceDll $StageEngineDir
    }
  }
}

$NativeErrorAction = $ErrorActionPreference
$OldPath = $env:PATH
$ErrorActionPreference = "Continue"
if ($SelectedToolchain -eq "msvc") {
  $env:PATH = @((Join-Path $QtMsvcRoot "bin"), $UcrtBinDir, $UsrBinDir, $OldPath) -join ";"
} else {
  $env:PATH = @($UcrtBinDir, $UsrBinDir, $OldPath) -join ";"
}
& $WinDeployQt --release --compiler-runtime --dir $StageDir (Join-Path $StageDir "CipherShell.exe") 2>&1 |
  Tee-Object -FilePath (Join-Path $ReportDir "windeployqt.log")
$WinDeployQtExitCode = $LASTEXITCODE
$env:PATH = $OldPath
$ErrorActionPreference = $NativeErrorAction
if ($WinDeployQtExitCode -ne 0) {
  throw "windeployqt failed; see $ReportDir\windeployqt.log"
}

$GuiRuntimeDlls = @()
$GuiRuntimeSourceDirs = @()
$ResolvedGuiDlls = [ordered]@{}
if ($SelectedToolchain -eq "msvc") {
  $GuiRuntimeSourceDirs += (Join-Path $QtMsvcRoot "bin")
  if ($ResolvedOpenSslRoot) {
    $GuiRuntimeSourceDirs += (Join-Path $ResolvedOpenSslRoot "bin")
  }
  $GuiRuntimeSourceDirs += Get-MsvcRuntimeSourceDirs $ResolvedVsDevCmd
  $GuiRuntimeSourceDirs += Get-WindowsKitBinDirs
  $GuiRuntimeSourceDirs += $UcrtBinDir
  $GuiRuntimeSourceDirs = $GuiRuntimeSourceDirs |
    Where-Object { $_ -and (Test-Path $_) } |
    Select-Object -Unique
  $GuiRuntimeDlls = Copy-ExistingDlls $GuiRuntimeSourceDirs $StageDir @(
    "libcrypto-3-x64.dll",
    "msvcp140.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "concrt140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "dxcompiler.dll",
    "dxil.dll"
  )
  $ResolvedGuiDlls = [ordered]@{
    mode = "msvc_targeted_runtime_copy"
    source_dirs = $GuiRuntimeSourceDirs
    copied = $GuiRuntimeDlls
  }
} else {
  # MSYS2's windeployqt can miss the MinGW/UCRT compiler runtime even with
  # --compiler-runtime. These DLLs must sit next to CipherShell.exe.
  $GuiRuntimeDlls = @(
    "libgcc_s_seh-1.dll",
    "libstdc++-6.dll",
    "libwinpthread-1.dll",
    "libcrypto-3-x64.dll"
  )
  Copy-RequiredDlls $UcrtBinDir $StageDir $GuiRuntimeDlls
  $GuiRuntimeSourceDirs += $UcrtBinDir
  $GuiRuntimeSourceDirs = $GuiRuntimeSourceDirs |
    Where-Object { $_ -and (Test-Path $_) } |
    Select-Object -Unique
  $ResolvedGuiDlls = Copy-ResolvedRuntimeDllClosure `
    -Root $StageDir `
    -DestinationDir $StageDir `
    -SourceDirs $GuiRuntimeSourceDirs `
    -ExcludeRoots @($StageEngineDir) `
    -Label "GUI"
}
$ResolvedEngineDlls = [ordered]@{}
if (Test-Path $StageEngineDir) {
  $ResolvedEngineDlls = Copy-ResolvedRuntimeDllClosure `
    -Root $StageEngineDir `
    -DestinationDir $StageEngineDir `
    -SourceDirs @($UsrBinDir) `
    -ExcludeRoots @() `
    -Label "engine"
}

Remove-Item -Force $PortableZip -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
  $StageDir,
  $PortableZip,
  [System.IO.Compression.CompressionLevel]::Optimal,
  $false)

$NsisScript = Join-Path $ReportDir "ciphershell.nsi"
$StageForNsis = $StageDir.Replace('\', '\\')
$InstallerForNsis = $InstallerExe.Replace('\', '\\')
@"
Unicode true
Name "CipherShell"
OutFile "$InstallerForNsis"
InstallDir "`$LOCALAPPDATA\Programs\CipherShell"
RequestExecutionLevel user
Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles
Section "Install"
  SetShellVarContext current
  IfFileExists "`$INSTDIR\Uninstall.exe" 0 skip_old_uninstall
  ExecWait '"`$INSTDIR\Uninstall.exe" /S _?=`$INSTDIR'
  Sleep 500
skip_old_uninstall:
  Delete "`$SMPROGRAMS\gmssh_client.lnk"
  Delete "`$SMPROGRAMS\GMSSH Client.lnk"
  Delete "`$SMPROGRAMS\GMSSH.lnk"
  Delete "`$DESKTOP\gmssh_client.lnk"
  Delete "`$DESKTOP\GMSSH Client.lnk"
  Delete "`$DESKTOP\GMSSH.lnk"
  RMDir /r "`$LOCALAPPDATA\Programs\gmssh_client"
  RMDir /r "`$LOCALAPPDATA\Programs\gmssh-client"
  RMDir /r "`$LOCALAPPDATA\Programs\GMSSH Client"
  SetOutPath "`$INSTDIR"
  File /r "$StageForNsis\\*.*"
  CreateDirectory "`$INSTDIR\log"
  FileOpen "`$0" "`$INSTDIR\log\audit.log" a
  FileClose "`$0"
  CreateDirectory "`$SMPROGRAMS"
  CreateShortCut "`$SMPROGRAMS\CipherShell.lnk" "`$INSTDIR\CipherShell.exe"
  CreateShortCut "`$DESKTOP\CipherShell.lnk" "`$INSTDIR\CipherShell.exe"
  WriteUninstaller "`$INSTDIR\Uninstall.exe"
SectionEnd
Section "Uninstall"
  SetShellVarContext current
  Delete "`$SMPROGRAMS\CipherShell.lnk"
  Delete "`$DESKTOP\CipherShell.lnk"
  Delete "`$SMPROGRAMS\gmssh_client.lnk"
  Delete "`$SMPROGRAMS\GMSSH Client.lnk"
  Delete "`$SMPROGRAMS\GMSSH.lnk"
  Delete "`$DESKTOP\gmssh_client.lnk"
  Delete "`$DESKTOP\GMSSH Client.lnk"
  Delete "`$DESKTOP\GMSSH.lnk"
  RMDir /r "`$INSTDIR"
SectionEnd
"@ | Set-Content -Encoding UTF8 -Path $NsisScript

$NativeErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $MakeNsis $NsisScript 2>&1 | Tee-Object -FilePath (Join-Path $ReportDir "makensis.log")
$MakeNsisExitCode = $LASTEXITCODE
$ErrorActionPreference = $NativeErrorAction
if ($MakeNsisExitCode -ne 0) {
  throw "makensis failed; see $ReportDir\makensis.log"
}

$PackageTestArgs = @{
  BuildDir = $BuildDir
  StageDir = $StageDir
  InstallerExe = $InstallerExe
  PortableZip = $PortableZip
  ReportDir = $ReportDir
  Toolchain = $SelectedToolchain
}
if ($RequireFullEngineBundle) {
  $PackageTestArgs["RequireFullEngineBundle"] = $true
}
if ($RequireWebTerminalBundle) {
  $PackageTestArgs["RequireWebTerminalBundle"] = $true
}
& (Join-Path $PSScriptRoot "test_windows_package.ps1") @PackageTestArgs 2>&1 |
  Tee-Object -FilePath (Join-Path $ReportDir "windows-package-test.log")
if ($LASTEXITCODE -ne 0) {
  throw "Windows package smoke test failed; see $ReportDir\windows-package-test.log"
}

$EngineDir = Join-Path $StageDir "bin"
$RequiredEngines = @("ssh.exe", "sftp.exe", "ssh-legacy-ecgm.exe", "sftp-legacy-ecgm.exe")
$RuntimeDlls = @{}
foreach ($Dll in $GuiRuntimeDlls) {
  $Path = Join-Path $StageDir $Dll
  $RuntimeDlls[$Dll] = [ordered]@{
    path = $Path
    exists = Test-Path $Path
  }
}
$Engines = @{}
foreach ($Engine in $RequiredEngines) {
  $Path = Join-Path $EngineDir $Engine
  $Engines[$Engine] = [ordered]@{
    path = $Path
    exists = Test-Path $Path
  }
}
$ModernEnginesPresent =
  (Test-Path (Join-Path $EngineDir "ssh.exe")) -and
  (Test-Path (Join-Path $EngineDir "sftp.exe"))
$LegacyEnginesPresent =
  (Test-Path (Join-Path $EngineDir "ssh-legacy-ecgm.exe")) -and
  (Test-Path (Join-Path $EngineDir "sftp-legacy-ecgm.exe"))
$EngineBundleStatus = if ($ModernEnginesPresent -and $LegacyEnginesPresent) {
  "full"
} elseif ($ModernEnginesPresent) {
  "modern_only"
} else {
  "none"
}

$Report = [ordered]@{
  verdict = "pass"
  root_dir = $RootDir
  build_dir = $BuildDir
  stage_dir = $StageDir
  executable = (Join-Path $StageDir "CipherShell.exe")
  portable_zip = $PortableZip
  installer_exe = $InstallerExe
  report_dir = $ReportDir
  tests = if ($SkipTests) { "skipped" } else { "pass" }
  windeployqt = "pass"
  nsis = "pass"
  package_smoke_test = "pass"
  package_smoke_test_report = $PackageTestReportPath
  toolchain = $SelectedToolchain
  qt_root = if ($QtMsvcRoot) { $QtMsvcRoot } else { "" }
  openssl_root = if ($ResolvedOpenSslRoot) { $ResolvedOpenSslRoot } else { "" }
  vsdevcmd = if ($ResolvedVsDevCmd) { $ResolvedVsDevCmd } else { "" }
  terminal_renderer = $TerminalRenderer
  engine_bundle = $EngineBundleStatus
  runtime_dlls = $RuntimeDlls
  resolved_gui_dlls = $ResolvedGuiDlls
  resolved_engine_dlls = $ResolvedEngineDlls
  engines = $Engines
}

$Report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $ReportPath
Write-Output "report=$ReportPath"
Write-Output "portable=$PortableZip"
Write-Output "installer=$InstallerExe"
