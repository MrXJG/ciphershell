param(
  [string]$BuildDir,
  [string]$Configuration = "Release",
  [switch]$SkipTests,
  [switch]$RequireFullEngineBundle
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
$PortableZip = Join-Path $BuildDir "ciphershell-0.1.0-win64-portable.zip"
$InstallerExe = Join-Path $BuildDir "ciphershell-0.1.0-win64-setup.exe"
$ReportPath = Join-Path $ReportDir "package-report.json"
$PackageTestReportPath = Join-Path $ReportDir "windows-package-test-report.json"

$Bash = "C:\msys64\usr\bin\bash.exe"
$WinDeployQt = "C:\msys64\ucrt64\bin\windeployqt.exe"
$MakeNsis = "C:\msys64\ucrt64\bin\makensis.exe"
$UcrtBinDir = "C:\msys64\ucrt64\bin"
$UsrBinDir = "C:\msys64\usr\bin"
$Objdump = Join-Path $UcrtBinDir "objdump.exe"

foreach ($Required in @($Bash, $WinDeployQt, $MakeNsis, $Objdump)) {
  if (!(Test-Path $Required)) {
    throw "Required tool not found: $Required"
  }
}

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

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

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

$BuildScript = @"
set -euo pipefail
export MSYSTEM=UCRT64
export PATH=/ucrt64/bin:/usr/bin:`$PATH
cmake -S '$RootMsys' -B '$BuildMsys' -G Ninja -DCMAKE_BUILD_TYPE='$Configuration'
cmake --build '$BuildMsys' --parallel `$(nproc)
$TestArg
"@

$NativeErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $Bash -lc $BuildScript 2>&1 | Tee-Object -FilePath (Join-Path $ReportDir "build-and-test.log")
$BuildExitCode = $LASTEXITCODE
$ErrorActionPreference = $NativeErrorAction
if ($BuildExitCode -ne 0) {
  throw "Build/test failed; see $ReportDir\build-and-test.log"
}

$AppExe = Join-Path $BuildDir "CipherShell.exe"
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

$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"
$NativeErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $WinDeployQt --release --compiler-runtime --dir $StageDir (Join-Path $StageDir "CipherShell.exe") 2>&1 |
  Tee-Object -FilePath (Join-Path $ReportDir "windeployqt.log")
$WinDeployQtExitCode = $LASTEXITCODE
$ErrorActionPreference = $NativeErrorAction
if ($WinDeployQtExitCode -ne 0) {
  throw "windeployqt failed; see $ReportDir\windeployqt.log"
}

# MSYS2's windeployqt can miss the MinGW/UCRT compiler runtime even with
# --compiler-runtime. These DLLs must sit next to CipherShell.exe.
$GuiRuntimeDlls = @(
  "libgcc_s_seh-1.dll",
  "libstdc++-6.dll",
  "libwinpthread-1.dll",
  "libcrypto-3-x64.dll"
)
Copy-RequiredDlls $UcrtBinDir $StageDir $GuiRuntimeDlls
$ResolvedGuiDlls = Copy-ResolvedRuntimeDllClosure `
  -Root $StageDir `
  -DestinationDir $StageDir `
  -SourceDirs @($UcrtBinDir) `
  -ExcludeRoots @($StageEngineDir) `
  -Label "GUI"
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
  Delete "`$SMPROGRAMS\CipherShell.lnk"
  Delete "`$DESKTOP\CipherShell.lnk"
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
}
if ($RequireFullEngineBundle) {
  $PackageTestArgs["RequireFullEngineBundle"] = $true
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
