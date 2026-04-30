param(
  [string]$InstallerExe,
  [string]$InstallDir,
  [string]$ReportDir,
  [switch]$SkipInstall,
  [switch]$SkipGuiLaunch,
  [switch]$SkipNetworkProbes,
  [string]$OpenEulerHost = "10.0.13.2",
  [int]$OpenEulerPort = 2222,
  [string]$KylinHost = "10.0.13.1",
  [int]$KylinPort = 22
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildDir = Join-Path $RootDir "build-win"
if ([string]::IsNullOrWhiteSpace($InstallerExe)) {
  $InstallerExe = Join-Path $BuildDir "ciphershell-0.1.0-win64-setup.exe"
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
  $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\CipherShell"
}
if ([string]::IsNullOrWhiteSpace($ReportDir)) {
  $ReportDir = Join-Path $BuildDir ("install-verification\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}

$InstallerExe = [System.IO.Path]::GetFullPath($InstallerExe)
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$ReportDir = [System.IO.Path]::GetFullPath($ReportDir)
$ReportPath = Join-Path $ReportDir "windows-install-validation-report.json"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)) "CipherShell.lnk"
$AuditLogPath = Join-Path $InstallDir "log\audit.log"
$Objdump = "C:\msys64\ucrt64\bin\objdump.exe"

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

function Assert-File([string]$Path, [string]$Label) {
  if (!(Test-Path $Path)) {
    throw "$Label missing: $Path"
  }
}

function Get-ImportedDlls([string]$Path) {
  Assert-File $Objdump "objdump"
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
    "mpr.dll", "msvcrt.dll", "ncrypt.dll", "netapi32.dll", "ntdll.dll",
    "ole32.dll", "oleacc.dll", "oleaut32.dll", "opengl32.dll",
    "powrprof.dll", "propsys.dll", "rpcrt4.dll", "secur32.dll",
    "setupapi.dll", "shcore.dll", "shell32.dll", "shlwapi.dll",
    "ucrtbase.dll", "user32.dll", "userenv.dll", "usp10.dll",
    "uxtheme.dll", "version.dll", "winhttp.dll", "winmm.dll",
    "winspool.drv", "ws2_32.dll", "wtsapi32.dll"
  )
  return $systemDlls -contains $lower
}

function Test-DllResolved([string]$DllName, [string[]]$SearchDirs) {
  if (Test-SystemDllName $DllName) {
    return $true
  }
  foreach ($dir in ($SearchDirs | Where-Object { $_ } | Select-Object -Unique)) {
    if (Test-Path (Join-Path $dir $DllName)) {
      return $true
    }
  }
  return $false
}

function Get-PeFiles([string]$Root) {
  Get-ChildItem -Recurse -File -Path $Root |
    Where-Object { $_.Extension.ToLowerInvariant() -in @(".exe", ".dll") }
}

function Assert-RecursiveImportsResolved([string]$PackageDir) {
  $engineDir = Join-Path $PackageDir "bin"
  $missing = @()
  foreach ($pe in (Get-PeFiles $PackageDir)) {
    $peDir = Split-Path -Parent $pe.FullName
    foreach ($dll in (Get-ImportedDlls $pe.FullName)) {
      if (!(Test-DllResolved $dll @($PackageDir, $peDir, $engineDir))) {
        $missing += "$($pe.FullName) -> $dll"
      }
    }
  }
  if ($missing.Count -gt 0) {
    throw ("Unresolved installed imports: {0}" -f ($missing -join "; "))
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

function Invoke-SshProbe(
  [string]$Label,
  [string]$SshPath,
  [string]$TargetHost,
  [int]$Port,
  [string]$Kex
) {
  $logPath = Join-Path $ReportDir "$Label.log"
  $knownHosts = Join-Path $ReportDir "$Label.known_hosts"
  $args = @(
    "-vvv",
    "-p", "$Port",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "UserKnownHostsFile=$knownHosts",
    "-o", "BatchMode=yes",
    "-o", "PreferredAuthentications=none",
    "-o", "NumberOfPasswordPrompts=0",
    "-o", "ConnectTimeout=10",
    "-o", "KexAlgorithms=$Kex",
    "-o", "HostKeyAlgorithms=sm2,sm2-cert",
    "-o", "PubkeyAcceptedAlgorithms=sm2,sm2-cert",
    "-o", "Ciphers=sm4-ctr",
    "-o", "MACs=hmac-sm3",
    "root@$TargetHost",
    "exit"
  )
  $oldPath = $env:PATH
  $oldErrorActionPreference = $ErrorActionPreference
  try {
    $engineDir = Split-Path -Parent $SshPath
    $env:PATH = @($engineDir, [Environment]::SystemDirectory, $env:WINDIR) -join ";"
    $ErrorActionPreference = "Continue"
    $output = & $SshPath @args 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $output | Set-Content -Encoding UTF8 -Path $logPath
  } finally {
    $env:PATH = $oldPath
    $ErrorActionPreference = $oldErrorActionPreference
  }
  $negotiated = $output -match "kex: algorithm: $([regex]::Escape($Kex))" -and
    $output -match "server->client cipher: sm4-ctr MAC: hmac-sm3"
  $authBoundary = $output -match "Authentications that can continue:" -or
    $output -match "Permission denied"
  $macIncorrect = $output -match "message authentication code incorrect"
  $status = if ($negotiated -and $authBoundary -and !$macIncorrect) {
    "pass"
  } elseif ($negotiated -and $macIncorrect) {
    "mac_incorrect"
  } else {
    "fail"
  }
  return [ordered]@{
    label = $Label
    host = $TargetHost
    port = $Port
    kex = $Kex
    exit_code = $exitCode
    negotiated = $negotiated
    auth_boundary = $authBoundary
    mac_incorrect = $macIncorrect
    status = $status
    log_path = $logPath
  }
}

if (!$SkipInstall) {
  Assert-File $InstallerExe "installer"
  $arguments = @("/S")
  if (![string]::IsNullOrWhiteSpace($InstallDir)) {
    $arguments += "/D=$InstallDir"
  }
  $installer = Start-Process -FilePath $InstallerExe -ArgumentList $arguments -Wait -PassThru
  if ($installer.ExitCode -ne 0) {
    throw "installer failed with exit code $($installer.ExitCode)"
  }
}

$App = Join-Path $InstallDir "CipherShell.exe"
$EngineDir = Join-Path $InstallDir "bin"
Assert-File $App "installed app"
Assert-File $DesktopShortcut "desktop shortcut"
foreach ($dll in @(
  "libfreetype-6.dll",
  "libharfbuzz-0.dll",
  "libpng16-16.dll",
  "libcrypto-3-x64.dll"
)) {
  Assert-File (Join-Path $InstallDir $dll) "installed runtime $dll"
}
foreach ($engine in @(
  "ssh.exe",
  "sftp.exe",
  "ssh-legacy-ecgm.exe",
  "sftp-legacy-ecgm.exe"
)) {
  Assert-File (Join-Path $EngineDir $engine) "installed engine $engine"
}

Assert-RecursiveImportsResolved $InstallDir

$SelfTest = Start-Process -FilePath $App -ArgumentList @("--self-test") -Wait -PassThru
if ($SelfTest.ExitCode -ne 0) {
  throw "CipherShell.exe --self-test failed with exit code $($SelfTest.ExitCode)"
}

$GuiLaunchStatus = "skipped"
if (!$SkipGuiLaunch) {
  $Gui = Start-Process -FilePath $App -PassThru
  Start-Sleep -Seconds 5
  if ($Gui.HasExited) {
    throw "GUI launch exited early with code $($Gui.ExitCode)"
  }
  Stop-Process -Id $Gui.Id -Force
  $GuiLaunchStatus = "pass"
}
Assert-File $AuditLogPath "installed audit log"

Test-EngineAlgorithms $EngineDir "ssh"
Test-EngineAlgorithms $EngineDir "ssh-legacy-ecgm"

$NetworkResults = @()
if (!$SkipNetworkProbes) {
  $NetworkResults += Invoke-SshProbe "openeuler-modern-sm2" `
    (Join-Path $EngineDir "ssh.exe") $OpenEulerHost $OpenEulerPort "sm2-sm3"
  $NetworkResults += Invoke-SshProbe "kylin-legacy-ecgm" `
    (Join-Path $EngineDir "ssh-legacy-ecgm.exe") $KylinHost $KylinPort "ecgm-sm2-sm3"
}

$Report = [ordered]@{
  verdict = "pass"
  installer = $InstallerExe
  install_dir = $InstallDir
  desktop_shortcut = [ordered]@{
    path = $DesktopShortcut
    exists = Test-Path $DesktopShortcut
  }
  audit_log = [ordered]@{
    path = $AuditLogPath
    exists = Test-Path $AuditLogPath
  }
  report_dir = $ReportDir
  self_test = "pass"
  gui_launch = $GuiLaunchStatus
  recursive_imports = "pass"
  engine_algorithms = "pass"
  network_probes = $NetworkResults
}

$Report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $ReportPath
Write-Output "windows_install_validation_report=$ReportPath"
