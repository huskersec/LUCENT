<#
.SYNOPSIS
    LUCENT golden-image baker - run INSIDE the target Windows VM, elevated.

.DESCRIPTION
    Idempotently installs the LUCENT toolchain and bakes the golden image:
      * M1/M2 oracle: Debugging Tools for Windows (cdb / gflags), VS 2022 C++
        Build Tools (cl.exe), Python 3.11 + deps; the Microsoft symbol path +
        pre-populated symbols; Full Page Heap pre-armed for vuln.exe (heap-class
        variants only - the stack baseline ignores it).
      * M3 tool layer: Adoptium Temurin JDK 21 (direct MSI, not winget), a
        version-pinned Ghidra extracted under C:\tools (with GHIDRA_INSTALL_DIR
        set), and ghidriff (pip) for binary patch-diffing.
    Then prints a pass/fail probe table: M1/M2 tools are required (gate the
    'golden' image); the M3 tool layer is informational.

    Run from an ELEVATED PowerShell prompt. After the required probes are green,
    take the vCenter snapshot the harness reverts to.

.NOTES
    Idempotent: re-running is safe. winget / pip skip already-installed packages,
    Ghidra + the JDK are version-pinned and skipped if already present, and the
    symbol / env steps are convergent. Large downloads use BITS (fast, resumable).
    Some tools (cl, python, java, ghidriff) land on PATH only in a FRESH shell
    after install - re-run there to see them go green.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    # Repo root; defaults to the directory this script lives in.
    [string]$RepoRoot = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
# Invoke-WebRequest in Windows PowerShell 5.1 throttles large downloads to a crawl
# while it renders a progress bar; silencing it is a 10-50x speedup. (Get-Download
# below prefers BITS, which is faster still and resumable.)
$ProgressPreference = 'SilentlyContinue'

function Write-Section([string]$Text) {
    Write-Host ""
    Write-Host "==== $Text ====" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# 0. Preflight - confirm winget is available.
# ---------------------------------------------------------------------------
Write-Section "Preflight"
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw "winget not found. Install 'App Installer' from the Microsoft Store, then re-run."
}
Write-Host "winget present: $((winget --version))"

# Helper: install a winget package idempotently (skips if already present).
function Install-WingetPackage {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [string]$Override
    )
    Write-Host "Installing $Id ..."
    $args = @(
        'install', '--id', $Id, '--exact',
        '--accept-package-agreements', '--accept-source-agreements',
        '--disable-interactivity'
    )
    if ($Override) { $args += @('--override', $Override) }
    # winget returns non-zero when the package is already installed / no upgrade;
    # treat those as success so the script stays idempotent.
    & winget @args
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host "  -> installed." -ForegroundColor Green
    }
    elseif ($code -eq -1978335189 -or $code -eq -1978335212) {
        # 0x8A15002B (no applicable upgrade) / 0x8A150014 (already installed)
        Write-Host "  -> already present (skipped)." -ForegroundColor DarkGray
    }
    else {
        Write-Warning "  -> winget exit $code for $Id (continuing; probe table will confirm)."
    }
}

# Helper: download a (large) file fast. BITS is much quicker than Invoke-WebRequest
# for big files and resumes on drop; fall back to IWR (progress bar already off) if
# the BITS service is unavailable.
function Get-Download {
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [Parameter(Mandatory)] [string]$OutFile
    )
    try {
        Start-BitsTransfer -Source $Uri -Destination $OutFile -ErrorAction Stop
    } catch {
        Write-Host "  (BITS unavailable: $($_.Exception.Message) - falling back to Invoke-WebRequest)" -ForegroundColor DarkGray
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile
    }
}

# ---------------------------------------------------------------------------
# 1. Windows SDK / Debugging Tools for Windows (cdb.exe, gflags.exe).
#    The SDK installer ships the Debuggers feature; cdb/gflags land under
#    'Windows Kits\10\Debuggers\x64'.
# ---------------------------------------------------------------------------
Write-Section "Windows SDK / Debugging Tools for Windows"
Install-WingetPackage -Id 'Microsoft.WindowsSDK.10.0.22621'

# ---------------------------------------------------------------------------
# 2. VS 2022 Build Tools with the C++ workload (cl.exe).
#    --override passes the VS bootstrapper the native desktop workload so cl.exe
#    and the x64 Native Tools environment are present.
# ---------------------------------------------------------------------------
Write-Section "VS 2022 Build Tools (C++ workload)"
$vsOverride = '--quiet --wait --norestart --nocache ' +
              '--add Microsoft.VisualStudio.Workload.VCTools ' +
              '--includeRecommended'
Install-WingetPackage -Id 'Microsoft.VisualStudio.2022.BuildTools' -Override $vsOverride

# ---------------------------------------------------------------------------
# 3. Python 3.11.
# ---------------------------------------------------------------------------
Write-Section "Python 3.11"
Install-WingetPackage -Id 'Python.Python.3.11'

# ---------------------------------------------------------------------------
# 4. Symbol store: C:\Symbols + machine-level _NT_SYMBOL_PATH.
# ---------------------------------------------------------------------------
Write-Section "Symbol path"
$symDir = 'C:\Symbols'
if (-not (Test-Path $symDir)) {
    New-Item -ItemType Directory -Path $symDir | Out-Null
    Write-Host "Created $symDir"
} else {
    Write-Host "$symDir already exists."
}
$symPath = "SRV*$symDir*https://msdl.microsoft.com/download/symbols"
[Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH', $symPath, 'Machine')
$env:_NT_SYMBOL_PATH = $symPath   # also set for the current session/probe
Write-Host "_NT_SYMBOL_PATH = $symPath"

# ---------------------------------------------------------------------------
# Locate cdb.exe (needed below and for the probe table). Search standard SDK
# debugger install locations under both Program Files trees.
# ---------------------------------------------------------------------------
function Find-First {
    param([string[]]$Patterns)
    foreach ($p in $Patterns) {
        $hit = Get-ChildItem -Path $p -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

$cdb = Find-First @(
    'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe',
    'C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe'
)

# ---------------------------------------------------------------------------
# 5. Pre-populate symbols for ntdll/kernelbase via a quick cdb "q" against a
#    stock binary, so the first real oracle run isn't blocked on downloads.
# ---------------------------------------------------------------------------
Write-Section "Symbol pre-population"
if ($cdb) {
    Write-Host "Using cdb: $cdb"
    foreach ($bin in @("$env:WINDIR\System32\ntdll.dll", "$env:WINDIR\System32\kernelbase.dll")) {
        if (Test-Path $bin) {
            Write-Host "  pre-fetching symbols for $bin ..."
            # Load the image, force symbol load, then quit. Output suppressed.
            & $cdb -y $symPath -c ".reload /f; ld *; q" -z $bin *> $null
        }
    }
    Write-Host "  symbol pre-fetch done." -ForegroundColor Green
} else {
    Write-Warning "cdb.exe not found yet; skipping symbol pre-population (probe table will flag it)."
}

# ---------------------------------------------------------------------------
# 6. Python dependencies from the repo requirements file (guard if missing).
# ---------------------------------------------------------------------------
Write-Section "Python dependencies"
$req = Join-Path $RepoRoot 'src\requirements.txt'
if (Test-Path $req) {
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($py) {
        Write-Host "pip install -r $req"
        & $py -m pip install --upgrade pip *> $null
        & $py -m pip install -r $req
    } else {
        Write-Warning "python not on PATH yet (new shell may be needed); skipping pip install."
    }
} else {
    Write-Warning "requirements file not found at $req; skipping pip install."
}

# ---------------------------------------------------------------------------
# 6b. M3 tool layer: JDK + Ghidra + ghidriff (binary patch-diffing).
#     ghidriff runs Ghidra headless, so it needs a JDK and a Ghidra install with
#     GHIDRA_INSTALL_DIR set. Required for M3 (the `diff` agent tool); NOT needed
#     for the M1/M2 oracle. Idempotent.
# ---------------------------------------------------------------------------
Write-Section "M3 tool layer (JDK + Ghidra + ghidriff)"

# Pinned Ghidra version + tools root (this VM installs tools under C:\tools).
# Bump $GhidraVer to move versions; the release tag is Ghidra_<ver>_build.
$ToolsRoot = 'C:\tools'
$GhidraVer = '12.0.4'

# JDK 21 (Ghidra 12.x requires JDK 21). Use Adoptium Temurin - the JDK Ghidra's
# install docs link - via a direct pinned MSI (like Ghidra), NOT winget: the
# winget Microsoft.OpenJDK package fails with an installer-hash mismatch. Bump
# $JdkTag/$JdkMsi to move versions.
$JdkTag = 'jdk-21.0.11+10'
$JdkMsi = 'OpenJDK21U-jdk_x64_windows_hotspot_21.0.11_10.msi'
$JdkUrl = "https://github.com/adoptium/temurin21-binaries/releases/download/$JdkTag/$JdkMsi"
if (Get-Command java -ErrorAction SilentlyContinue) {
    Write-Host "java already on PATH: $((Get-Command java).Source)" -ForegroundColor DarkGray
} else {
    try {
        $msi = Join-Path $env:TEMP $JdkMsi
        Write-Host "Downloading Temurin JDK ($JdkTag) ..."
        Get-Download -Uri $JdkUrl -OutFile $msi
        Write-Host "Installing $JdkMsi (silent) ..."
        # FeatureEnvironment => add java to PATH; FeatureJavaHome => set JAVA_HOME.
        $jp = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
            '/i', "`"$msi`"", '/qn', '/norestart',
            'ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJavaHome')
        if ($jp.ExitCode -eq 0) { Write-Host "  -> Temurin JDK installed." -ForegroundColor Green }
        else { Write-Warning "  -> msiexec exit $($jp.ExitCode) for the JDK." }
        Remove-Item $msi -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Temurin JDK install failed: $($_.Exception.Message)"
        Write-Warning "Install manually from adoptium.net (Temurin 21, Windows x64 MSI)."
    }
}

# Ghidra: download the PINNED PUBLIC release (by release tag, so no build-date
# guessing) and extract under C:\tools.  GHIDRA_INSTALL_DIR points at the extract.
if (-not (Test-Path $ToolsRoot)) { New-Item -ItemType Directory -Path $ToolsRoot | Out-Null }
$ghidraHome = $null
$existing = Get-ChildItem -Path $ToolsRoot -Directory -Filter "ghidra_${GhidraVer}_PUBLIC" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existing) {
    $ghidraHome = $existing.FullName
    Write-Host "Ghidra $GhidraVer already present: $ghidraHome" -ForegroundColor DarkGray
} else {
    try {
        $tag = "Ghidra_${GhidraVer}_build"
        Write-Host "Resolving Ghidra $GhidraVer (release tag $tag) from GitHub..."
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/$tag" -Headers @{ 'User-Agent' = 'lucent-setup' }
        $asset = $rel.assets | Where-Object { $_.name -like "ghidra_${GhidraVer}_PUBLIC_*.zip" } | Select-Object -First 1
        if (-not $asset) { throw "no ghidra_${GhidraVer}_PUBLIC_*.zip asset under tag $tag" }
        $zip = Join-Path $env:TEMP $asset.name
        Write-Host "Downloading $($asset.name) (this is large) ..."
        Get-Download -Uri $asset.browser_download_url -OutFile $zip
        Write-Host "Extracting to $ToolsRoot ..."
        Expand-Archive -Path $zip -DestinationPath $ToolsRoot -Force
        Remove-Item $zip -ErrorAction SilentlyContinue
        $existing = Get-ChildItem -Path $ToolsRoot -Directory -Filter "ghidra_${GhidraVer}_PUBLIC" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($existing) { $ghidraHome = $existing.FullName }
    } catch {
        Write-Warning "Ghidra $GhidraVer install failed: $($_.Exception.Message)"
        Write-Warning "Install manually: download ghidra_${GhidraVer}_PUBLIC from github.com/NationalSecurityAgency/ghidra/releases, extract to $ToolsRoot, then set GHIDRA_INSTALL_DIR."
    }
}
if ($ghidraHome) {
    [Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR', $ghidraHome, 'Machine')
    $env:GHIDRA_INSTALL_DIR = $ghidraHome
    Write-Host "GHIDRA_INSTALL_DIR = $ghidraHome" -ForegroundColor Green
}

# ghidriff (pip; a Python package - it does NOT live under C:\tools like Ghidra
# does; its console script lands in Python's Scripts dir). It uses PyGhidra, which
# reads GHIDRA_INSTALL_DIR at RUN time. Latest ghidriff is the version most likely
# to support a NEW Ghidra (12.x); if the diff step errors with a Ghidra API
# mismatch, pin ghidriff to a release that lists Ghidra 12 support (or drop Ghidra
# to ghidriff's tested version).
$pyForGh = (Get-Command python -ErrorAction SilentlyContinue).Source
if ($pyForGh) {
    Write-Host "pip install --upgrade ghidriff (latest)"
    & $pyForGh -m pip install --upgrade ghidriff
} else {
    Write-Warning "python not on PATH yet; skipping 'pip install ghidriff' (re-run in a fresh shell)."
}

# ---------------------------------------------------------------------------
# 7. Probe table - pass/fail for each required tool, searching standard
#    install locations. This is the authoritative 'is the golden image ready?'
#    check.
# ---------------------------------------------------------------------------
Write-Section "Probe table"

$tttracer = Find-First @(
    'C:\Windows\System32\tttracer.exe',
    'C:\Program Files\WindowsApps\Microsoft.WinDbg*\tttracer.exe'
)
$gflags = Find-First @(
    'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe',
    'C:\Program Files\Windows Kits\10\Debuggers\x64\gflags.exe'
)
$cl = Find-First @(
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe',
    'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe',
    'C:\Program Files\Microsoft Visual Studio\2022\*\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe'
)
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) {
    $python = Find-First @(
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        'C:\Program Files\Python311\python.exe',
        'C:\Python311\python.exe'
    )
}

$probes = @(
    [pscustomobject]@{ Tool = 'cl.exe';       Path = $cl },
    [pscustomobject]@{ Tool = 'cdb.exe';      Path = $cdb },
    [pscustomobject]@{ Tool = 'gflags.exe';   Path = $gflags },
    [pscustomobject]@{ Tool = 'tttracer.exe'; Path = $tttracer },
    [pscustomobject]@{ Tool = 'python';       Path = $python }
)

$allOk = $true
$probes | ForEach-Object {
    $ok = [bool]$_.Path -and (Test-Path $_.Path)
    if (-not $ok) { $allOk = $false }
    $status = if ($ok) { 'PASS' } else { 'FAIL' }
    $color  = if ($ok) { 'Green' } else { 'Red' }
    $shown  = if ($_.Path) { $_.Path } else { '(not found)' }
    Write-Host ("  {0,-13} {1,-4}  {2}" -f $_.Tool, $status, $shown) -ForegroundColor $color
}

# M3 tool-layer probes - informational; NOT part of the M1/M2 golden bar, so a
# FAIL here (often just PATH lag in this session) does not flip $allOk. ghidriff
# and java land on PATH only in a fresh shell after install.
$java = (Get-Command java -ErrorAction SilentlyContinue).Source
$ghidraHeadless = if ($env:GHIDRA_INSTALL_DIR) { Join-Path $env:GHIDRA_INSTALL_DIR 'support\analyzeHeadless.bat' } else { $null }
$ghidriff = (Get-Command ghidriff -ErrorAction SilentlyContinue).Source
$m3probes = @(
    [pscustomobject]@{ Tool = 'java';     Path = $java },
    [pscustomobject]@{ Tool = 'ghidra';   Path = $ghidraHeadless },
    [pscustomobject]@{ Tool = 'ghidriff'; Path = $ghidriff }
)
Write-Host "  -- M3 tool layer (needed for M3, not M1/M2) --" -ForegroundColor DarkGray
$m3probes | ForEach-Object {
    $ok = [bool]$_.Path -and (Test-Path $_.Path)
    $status = if ($ok) { 'PASS' } else { 'FAIL' }
    $color  = if ($ok) { 'Green' } else { 'Yellow' }
    $shown  = if ($_.Path) { $_.Path } else { '(not found)' }
    Write-Host ("  {0,-13} {1,-4}  {2}" -f $_.Tool, $status, $shown) -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# 8. Pre-arm Full Page Heap for the target image (HEAP-class variants only).
#    NOTE: the current baseline is the STACK-overflow fixture (vuln.exe), which
#    does NOT use page heap - page heap instruments the heap, and the oracle is
#    called with page_heap=False for it. This step is harmless pre-arming for
#    when we climb to the 1_heap-overflow / 2_use-after-free museum variants.
#    gflags writes a GlobalFlag/PageHeapFlags entry under the image's Image File
#    Execution Options registry key, keyed by IMAGE NAME (vuln.exe) - NOT by
#    full path. That registry entry is captured by the golden snapshot, so every
#    reverted trial starts with page heap already armed for heap-class runs.
#    Idempotent: re-enabling is a no-op rewrite of the same registry value.
# ---------------------------------------------------------------------------
Write-Section "Full Page Heap pre-arm (vuln.exe - heap-class variants only)"
$imageName = 'vuln.exe'
if ($gflags) {
    Write-Host "Using gflags: $gflags"
    # Enable full page heap keyed on the image name (how gflags matches at launch).
    & $gflags /p /enable $imageName /full | Out-Null

    # Confirm by parsing `gflags /p` (lists images with page heap enabled).
    $pageHeapList = & $gflags /p 2>&1
    $targetLine = $pageHeapList | Where-Object { $_ -match [regex]::Escape($imageName) }
    if ($targetLine) {
        Write-Host "  $imageName`: page heap enabled" -ForegroundColor Green
        $targetLine | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        $pageHeapOk = $true
    } else {
        Write-Warning "  gflags /p did not list $imageName - page heap may NOT be enabled."
        $pageHeapOk = $false
    }
    Write-Host "  (persists in the registry => survives into the golden snapshot.)" -ForegroundColor DarkGray
} else {
    Write-Warning "gflags.exe not found; cannot enable page heap. Install Debugging Tools for Windows and re-run."
    $pageHeapOk = $false
}

# ---------------------------------------------------------------------------
# 9. Final reminder.
# ---------------------------------------------------------------------------
Write-Section "Next step"
if ($allOk) {
    Write-Host "All required probes PASS." -ForegroundColor Green
    if ($pageHeapOk) {
        Write-Host "Page heap is pre-armed for vuln.exe (only matters for heap-class variants)." -ForegroundColor DarkGray
    }
} else {
    Write-Warning "One or more probes FAILED. Open a fresh elevated shell (to pick up PATH/env changes) and re-run; some tools require a new session."
}
Write-Host ""
Write-Host ">> The current baseline is the STACK-overflow fixture (vuln.exe); it does NOT need page heap." -ForegroundColor Yellow
Write-Host ">> To finish the golden image:" -ForegroundColor Yellow
Write-Host "     1. Build the fixture: run bench\build.bat (it self-forces the x64 toolchain) => vuln.exe + vuln.pdb in C:\lucent\sandbox." -ForegroundColor Yellow
Write-Host "     2. Sanity-check locally: python bench\verify_oracle.py  (expect crash-64A crashed=True, clean-8A crashed=False)." -ForegroundColor Yellow
Write-Host "     3. Take the vCenter snapshot and name it 'golden' - that snapshot is what the harness reverts to before each trial." -ForegroundColor Yellow
