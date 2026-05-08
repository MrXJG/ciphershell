param(
  [string]$BuildDir,
  [string]$StageDir,
  [string]$InstallerExe,
  [string]$PortableZip,
  [string]$ReportDir,
  [switch]$RequireFullEngineBundle,
  [switch]$RequireWebTerminalBundle,
  [switch]$SkipInstaller,
  [ValidateSet("auto", "msys2", "msvc")]
  [string]$Toolchain = "auto"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
  $BuildDir = Join-Path $RootDir "build-win"
}
$BuildDir = [System.IO.Path]::GetFullPath($BuildDir)
if ([string]::IsNullOrWhiteSpace($StageDir)) {
  $StageDir = Join-Path $BuildDir "package\ciphershell"
}
if ([string]::IsNullOrWhiteSpace($InstallerExe)) {
  $InstallerExe = Join-Path $BuildDir "ciphershell-0.1.0-win64-setup.exe"
}
if ([string]::IsNullOrWhiteSpace($PortableZip)) {
  $PortableZip = Join-Path $BuildDir "ciphershell-0.1.0-win64-portable.zip"
}
if ([string]::IsNullOrWhiteSpace($ReportDir)) {
  $ReportDir = Join-Path $BuildDir ("package-verification\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}

$ReportDir = [System.IO.Path]::GetFullPath($ReportDir)
$ReportPath = Join-Path $ReportDir "windows-package-test-report.json"
$Objdump = "C:\msys64\ucrt64\bin\objdump.exe"
$SystemSearchDirs = @(
  [Environment]::SystemDirectory,
  $env:WINDIR,
  (Join-Path $env:WINDIR "System32")
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Assert-File([string]$Path, [string]$Label) {
  if (!(Test-Path $Path)) {
    throw "$Label missing: $Path"
  }
}

function Expand-ZipNoProgress([string]$ZipPath, [string]$DestinationPath) {
  if (Test-Path $DestinationPath) {
    Remove-Item -Recurse -Force $DestinationPath
  }
  New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
  [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestinationPath)
}

function Get-ImportedDlls([string]$ExePath) {
  if (!(Test-Path $Objdump)) {
    throw "objdump not found: $Objdump"
  }
  $lines = & $Objdump -p $ExePath 2>$null | Select-String "DLL Name:"
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

function Test-DllResolved([string]$DllName, [string[]]$SearchDirs) {
  if (Test-SystemDllName $DllName) {
    return $true
  }
  if ($DllName -like "api-ms-win-crt-*" -and
      (Test-DllResolved "ucrtbase.dll" $SearchDirs)) {
    return $true
  }
  foreach ($dir in ($SearchDirs + $SystemSearchDirs)) {
    if ($dir -and (Test-Path (Join-Path $dir $DllName))) {
      return $true
    }
  }
  return $false
}

function Assert-ImportsResolved([string]$ExePath, [string[]]$SearchDirs) {
  $missing = @()
  foreach ($dll in (Get-ImportedDlls $ExePath)) {
    if (!(Test-DllResolved $dll $SearchDirs)) {
      $missing += $dll
    }
  }
  if ($missing.Count -gt 0) {
    throw ("Unresolved imports for {0}: {1}" -f $ExePath, ($missing -join ", "))
  }
}

function Get-PeFiles([string]$Root) {
  Get-ChildItem -Recurse -File -Path $Root |
    Where-Object { $_.Extension.ToLowerInvariant() -in @(".exe", ".dll") }
}

function Assert-PackageImportsResolved([string]$PackageDir) {
  $missing = @()
  $engineDir = Join-Path $PackageDir "bin"
  $targets = @()
  if ($Toolchain -eq "msvc") {
    $targets += @(
      (Join-Path $PackageDir "CipherShell.exe"),
      (Join-Path $PackageDir "QtWebEngineProcess.exe"),
      (Join-Path $PackageDir "platforms\\qwindows.dll"),
      (Join-Path $engineDir "ssh.exe"),
      (Join-Path $engineDir "sftp.exe"),
      (Join-Path $engineDir "ssh-legacy-ecgm.exe"),
      (Join-Path $engineDir "sftp-legacy-ecgm.exe")
    ) | Where-Object { Test-Path $_ }
  } else {
    $targets += (Get-PeFiles $PackageDir | ForEach-Object { $_.FullName })
  }
  foreach ($path in $targets) {
    $pe = Get-Item $path
    $peDir = Split-Path -Parent $pe.FullName
    foreach ($dll in (Get-ImportedDlls $pe.FullName)) {
      if (!(Test-DllResolved $dll @($PackageDir, $peDir, $engineDir))) {
        $missing += "$($pe.FullName) -> $dll"
      }
    }
  }
  if ($missing.Count -gt 0) {
    throw ("Unresolved package imports: {0}" -f ($missing -join "; "))
  }
}

function Assert-WebTerminalBundle([string]$PackageDir, [string]$Name) {
  $app = Join-Path $PackageDir "CipherShell.exe"
  $imports = Get-ImportedDlls $app
  if (!($imports -contains "Qt6WebEngineWidgets.dll")) {
    throw "$Name missing Qt6WebEngineWidgets runtime dependency in CipherShell.exe imports"
  }
  if (!($imports -contains "Qt6WebChannel.dll")) {
    throw "$Name missing Qt6WebChannel runtime dependency in CipherShell.exe imports"
  }

  Assert-File (Join-Path $PackageDir "Qt6WebEngineWidgets.dll") "$Name web runtime Qt6WebEngineWidgets.dll"
  Assert-File (Join-Path $PackageDir "Qt6WebEngineCore.dll") "$Name web runtime Qt6WebEngineCore.dll"
  Assert-File (Join-Path $PackageDir "Qt6WebChannel.dll") "$Name web runtime Qt6WebChannel.dll"

  $processCandidates = @(
    (Join-Path $PackageDir "QtWebEngineProcess.exe"),
    (Join-Path $PackageDir "bin\\QtWebEngineProcess.exe"),
    (Join-Path $PackageDir "resources\\QtWebEngineProcess.exe")
  )
  if (!($processCandidates | Where-Object { Test-Path $_ })) {
    throw "$Name missing QtWebEngineProcess.exe"
  }

  $resourcesDir = Join-Path $PackageDir "resources"
  if (!(Test-Path $resourcesDir)) {
    throw "$Name missing web runtime resources directory: $resourcesDir"
  }
  $webResources = @(Get-ChildItem -Path $resourcesDir -File -Filter "qtwebengine*.pak" -ErrorAction SilentlyContinue)
  if ($webResources.Count -lt 2) {
    throw "$Name missing qtwebengine resource pak files in $resourcesDir"
  }

  $localeDirs = @(
    (Join-Path $PackageDir "translations\\qtwebengine_locales"),
    (Join-Path $PackageDir "qtwebengine_locales")
  )
  $localeDir = $localeDirs | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ([string]::IsNullOrWhiteSpace($localeDir)) {
    throw "$Name missing qtwebengine locales directory"
  }
  $localePaks = @(Get-ChildItem -Path $localeDir -File -Filter "*.pak" -ErrorAction SilentlyContinue)
  if ($localePaks.Count -lt 1) {
    throw "$Name missing qtwebengine locale packs in $localeDir"
  }
}

function Invoke-CleanPath([scriptblock]$Body, [string[]]$PathEntries) {
  $oldPath = $env:PATH
  try {
    $env:PATH = ($PathEntries | Where-Object { $_ } | Select-Object -Unique) -join ";"
    & $Body
  } finally {
    $env:PATH = $oldPath
  }
}

function Assert-Contains([string[]]$Lines, [string]$Expected, [string]$Label) {
  if (!($Lines -contains $Expected)) {
    throw "$Label missing expected value: $Expected"
  }
}

function Test-EngineAlgorithms([string]$EngineDir, [string]$Prefix) {
  $ssh = Join-Path $EngineDir "$Prefix.exe"
  Assert-File $ssh "$Prefix engine"
  Invoke-CleanPath -PathEntries @($EngineDir, [Environment]::SystemDirectory, $env:WINDIR) -Body {
    $kex = & $ssh -Q kex
    $key = & $ssh -Q key
    $cipher = & $ssh -Q cipher
    $mac = & $ssh -Q mac
    if ($LASTEXITCODE -ne 0) {
      throw "$Prefix -Q checks failed with exit code $LASTEXITCODE"
    }
    Assert-Contains $kex "ecgm-sm2-sm3" "$Prefix kex"
    Assert-Contains $kex "sm2-sm3" "$Prefix kex"
    Assert-Contains $key "sm2" "$Prefix key"
    Assert-Contains $cipher "sm4-ctr" "$Prefix cipher"
    Assert-Contains $mac "hmac-sm3" "$Prefix mac"
  }
}

function Test-PackageTree([string]$PackageDir, [string]$Name) {
  $app = Join-Path $PackageDir "CipherShell.exe"
  $engineDir = Join-Path $PackageDir "bin"
  $modernSsh = Join-Path $engineDir "ssh.exe"
  $modernSftp = Join-Path $engineDir "sftp.exe"
  $legacySsh = Join-Path $engineDir "ssh-legacy-ecgm.exe"
  $legacySftp = Join-Path $engineDir "sftp-legacy-ecgm.exe"
  $appImports = Get-ImportedDlls $app
  $runtimeFlavor = if (($appImports -contains "libstdc++-6.dll") -or ($appImports -contains "libgcc_s_seh-1.dll")) {
    "mingw"
  } else {
    "msvc"
  }

  Assert-File $app "$Name CipherShell.exe"
  foreach ($dll in @("msys-2.0.dll", "msys-crypto-3.dll", "msys-z.dll", "msys-gcc_s-seh-1.dll")) {
    Assert-File (Join-Path $engineDir $dll) "$Name engine runtime $dll"
  }
  Assert-File $modernSsh "$Name modern ssh.exe"
  Assert-File $modernSftp "$Name modern sftp.exe"
  if ($RequireFullEngineBundle) {
    Assert-File $legacySsh "$Name legacy ssh-legacy-ecgm.exe"
    Assert-File $legacySftp "$Name legacy sftp-legacy-ecgm.exe"
  }

  Assert-PackageImportsResolved $PackageDir
  if ($RequireWebTerminalBundle) {
    Assert-WebTerminalBundle $PackageDir $Name
  }

  Invoke-CleanPath -PathEntries @($PackageDir, $engineDir, [Environment]::SystemDirectory, $env:WINDIR) -Body {
    & $app --self-test
    if ($LASTEXITCODE -ne 0) {
      throw "$Name CipherShell.exe --self-test failed with exit code $LASTEXITCODE"
    }
  }

  Test-EngineAlgorithms $engineDir "ssh"
  if (Test-Path $legacySsh) {
    Test-EngineAlgorithms $engineDir "ssh-legacy-ecgm"
  }

  return [ordered]@{
    name = $Name
    package_dir = $PackageDir
    runtime_flavor = $runtimeFlavor
    self_test = "pass"
    imports = "pass"
    web_terminal_bundle = if ($RequireWebTerminalBundle) { "pass" } else { "not_required" }
    modern_engine = "pass"
    legacy_engine = if ((Test-Path $legacySsh) -and (Test-Path $legacySftp)) { "pass" } else { "missing" }
  }
}

$Results = @()
$Results += Test-PackageTree $StageDir "stage"

Assert-File $PortableZip "portable zip"
$PortableExtractDir = Join-Path $ReportDir "portable-extract"
Expand-ZipNoProgress -ZipPath $PortableZip -DestinationPath $PortableExtractDir
$Results += Test-PackageTree $PortableExtractDir "portable_zip"

if (!$SkipInstaller) {
  Assert-File $InstallerExe "installer"
  $InstallDir = Join-Path $ReportDir "installed-smoke"
  Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
  $installer = Start-Process -FilePath $InstallerExe -ArgumentList @("/S", "/D=$InstallDir") -Wait -PassThru
  if ($installer.ExitCode -ne 0) {
    throw "installer failed with exit code $($installer.ExitCode)"
  }
  $Results += Test-PackageTree $InstallDir "silent_install"
}

$Report = [ordered]@{
  verdict = "pass"
  report_path = $ReportPath
  toolchain = $Toolchain
  require_full_engine_bundle = [bool]$RequireFullEngineBundle
  results = $Results
}

$Report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $ReportPath
Write-Output "windows_package_test_report=$ReportPath"
