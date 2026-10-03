# Installs AgentGate into Cline on Windows: the plugin, the skill, and a check
# that the Kev server is reachable. Never starts or stops Kev.
#
# From a clone:   powershell -ExecutionPolicy Bypass -File .\install.ps1 [-WithKev] [-Uninstall]
# Without one:    irm https://raw.githubusercontent.com/kaihere14/agent-gate/main/install.ps1 | iex
#
#   -WithKev     also clone Kev into $env:KEV_DIR (default ~\kev) and install its
#                dependencies with uv; it prints the command to start the server
#   -Uninstall   remove the skill and an installed copy of the plugin
#
# Env: CLINE_DIR (default ~\.cline, same as Cline), AGENTGATE_REPO (owner/name on
# GitHub, default kaihere14/agent-gate, used only without a clone), AGENTGATE_REF (default main),
# KEV_URL (default http://localhost:8008/v1/systemone), KEV_DIR (default ~\kev).
param([switch]$WithKev, [switch]$Uninstall)
$ErrorActionPreference = "Stop"

$ClineDir = if ($env:CLINE_DIR) { $env:CLINE_DIR } else { Join-Path $HOME ".cline" }
$Dest = Join-Path $ClineDir "plugins\agent-gate"
$SkillDir = Join-Path $ClineDir "skills\agent-gate"
$Marker = ".installed-by-agent-gate"
$KevUrl = if ($env:KEV_URL) { $env:KEV_URL } else { "http://localhost:8008/v1/systemone" }
$KevDir = if ($env:KEV_DIR) { $env:KEV_DIR } else { Join-Path $HOME "kev" }
$Ref = if ($env:AGENTGATE_REF) { $env:AGENTGATE_REF } else { "main" }
$Repo = if ($env:AGENTGATE_REPO) { $env:AGENTGATE_REPO } else { "kaihere14/agent-gate" }

function Say($m) { Write-Host "==> $m" }
function Warn($m) { Write-Host "warning: $m" -ForegroundColor Yellow }
# throw, not exit: under `irm | iex` exit would close the user's PowerShell window.
function Die($m) { throw "agent-gate install: $m" }

if ($Uninstall) {
  if (Test-Path (Join-Path $SkillDir $Marker)) { Remove-Item -Recurse -Force $SkillDir; Say "removed skill $SkillDir" }
  if (Test-Path (Join-Path $Dest $Marker)) {
    Remove-Item -Recurse -Force $Dest
    Say "removed $Dest"
  } elseif (Test-Path $Dest) {
    Warn "$Dest was not created by this installer (no $Marker), so it was left in place"
  }
  return
}

# 1. Find the source: the folder this script is in, or a download from GitHub.
$Src = $null
if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "plugin\gate.ts"))) {
  $Src = (Resolve-Path $PSScriptRoot).Path
} else {
  $Tmp = Join-Path ([IO.Path]::GetTempPath()) ("agent-gate-" + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $Tmp | Out-Null
  Say "downloading $Repo@$Ref"
  $Zip = Join-Path $Tmp "src.zip"
  Invoke-WebRequest -UseBasicParsing -Uri "https://codeload.github.com/$Repo/zip/$Ref" -OutFile $Zip
  Expand-Archive -Path $Zip -DestinationPath $Tmp
  $Src = (Get-ChildItem -Path $Tmp -Directory | Select-Object -First 1).FullName
  if (-not (Test-Path (Join-Path $Src "plugin\gate.ts"))) { Die "download does not contain plugin\gate.ts" }
}

# 2. Cline itself.
if (Get-Command cline -ErrorAction SilentlyContinue) {
  Say "found cline $(cline --version 2>$null | Select-Object -First 1)"
} else {
  Warn "cline is not on PATH; install it with: npm install -g cline"
}

# 3. The plugin. Cline loads every plugin listed in package.json under $ClineDir\plugins.
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
if ((Resolve-Path $Dest).Path -eq $Src) {
  Say "plugin already lives at $Dest (running from it), nothing to copy"
} else {
  Say "installing plugin to $Dest"
  foreach ($item in "plugin", "skill", "viewer", "scripts") {
    $target = Join-Path $Dest $item
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    Copy-Item -Recurse -Path (Join-Path $Src $item) -Destination $target
  }
  Copy-Item -Force (Join-Path $Src "package.json"), (Join-Path $Src "README.md") $Dest
  New-Item -ItemType File -Force -Path (Join-Path $Dest $Marker) | Out-Null
}

# 4. The skill. Cline reads <dir>\SKILL.md from each folder in $ClineDir\skills.
# Copied, not linked: symlinks need admin rights or Developer Mode on Windows.
if ((Test-Path $SkillDir) -and -not (Test-Path (Join-Path $SkillDir $Marker))) {
  Warn "$SkillDir exists and was not created by this installer, so the skill was not installed"
} else {
  if (Test-Path $SkillDir) { Remove-Item -Recurse -Force $SkillDir }
  Copy-Item -Recurse -Path (Join-Path $Src "skill") -Destination $SkillDir
  New-Item -ItemType File -Force -Path (Join-Path $SkillDir $Marker) | Out-Null
  Say "installed skill to $SkillDir"
}

# 5. Kev (optional download, never started here).
if ($WithKev) {
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Die "git is required for -WithKev" }
  if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { Die "uv is required for -WithKev: powershell -c `"irm https://astral.sh/uv/install.ps1 | iex`"" }
  if (Test-Path (Join-Path $KevDir ".git")) { Say "Kev already cloned at $KevDir" } else { git clone https://github.com/jaredpalmer/kev.git $KevDir }
  Say "installing Kev dependencies (uv sync --extra serve)"
  Push-Location $KevDir; try { uv sync --extra serve } finally { Pop-Location }
}

$Origin = ([Uri]$KevUrl).GetLeftPart([UriPartial]::Authority)
$up = $false
try {
  Invoke-WebRequest -UseBasicParsing -Uri $Origin -TimeoutSec 2 | Out-Null
  $up = $true
} catch {
  # Any HTTP answer (even 404) means the server is up; only a failed connection means down.
  if ($_.Exception.Response) { $up = $true }
}
if ($up) {
  Say "Kev is reachable at $Origin"
} else {
  Warn "Kev is not running at $Origin. Until it is, Cline stops each task with setup steps."
  Write-Host @"
    Kev needs a CUDA or ROCm GPU on Windows. Download and start it:
      git clone https://github.com/jaredpalmer/kev.git $KevDir; cd $KevDir
      uv sync --extra serve
      uv run --extra serve python -m kev.serve --run jaredpalmer/kev-4b --port 8008
    Or run with the hard rules only: `$env:AGENTGATE_MODE = "rules"
"@
}

Say "done. Restart Cline so it loads the plugin and the skill."
