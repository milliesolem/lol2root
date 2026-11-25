## core.nim - shared types, helpers, reporter and rendering.
##
## Every check module imports this file and adds findings through a Reporter.
## Rendering is deliberately split from data collection so that the console
## output stays clean and the JSON output stays machine-readable.

import std/[os, osproc, strutils, json, times, algorithm, sequtils, sets, tables]

const
  version* = "0.1.0"
  toolName* = "lol2root"

type
  Severity* = enum
    sevInfo = "info",
    sevLow = "low",
    sevMed = "medium",
    sevHigh = "high",
    sevCritical = "critical"

  Finding* = object
    id*: string
    category*: string
    title*: string
    detail*: string
    severity*: Severity
    refs*: seq[string]

  Options* = object
    color*: bool          ## force ANSI colors on/off (auto when unset)
    jsonLog*: bool        ## emit a JSON report
    jsonPath*: string     ## where to write the JSON report
    exploit*: bool        ## run automated exploitation where supported
    all*: bool            ## run heavier/slower checks too
    only*: HashSet[string] ## when non-empty, restrict to these categories
    quiet*: bool          ## print only critical/high findings
    outputFile*: string   ## also write console output to this file
    timeoutSec*: int      ## default per-command timeout

  Reporter* = ref object
    findings*: seq[Finding]
    started*: DateTime

  CheckDef* = object
    id*: string
    category*: string
    title*: string
    run*: proc(opts: Options, rep: Reporter) {.closure.}

  Registry* = ref object
    defs*: seq[CheckDef]

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

const
  ansiReset = "\e[0m"
  ansiBold = "\e[1m"
  ansiDim = "\e[2m"
  ansiRed = "\e[31m"
  ansiGreen = "\e[32m"
  ansiYellow = "\e[33m"
  ansiBlue = "\e[34m"
  ansiMagenta = "\e[35m"
  ansiCyan = "\e[36m"
  ansiBrightRed = "\e[91m"

proc paint*(s, code: string; on: bool): string =
  if on and s.len > 0: code & s & ansiReset else: s

proc severityTag*(s: Severity): string =
  case s
  of sevCritical: "CRIT"
  of sevHigh: "HIGH"
  of sevMed: "MED "
  of sevLow: "LOW "
  of sevInfo: "INFO"

proc severityColor*(s: Severity): string =
  case s
  of sevCritical: ansiBrightRed
  of sevHigh: ansiRed
  of sevMed: ansiYellow
  of sevLow: ansiCyan
  of sevInfo: ansiDim

proc severityOrder*(s: Severity): int = ord(s)

# ---------------------------------------------------------------------------
# Process / file helpers
# ---------------------------------------------------------------------------

proc which*(bin: string): bool =
  ## True when `bin` is available on PATH.
  try:
    result = findExe(bin).len > 0
  except OSError:
    result = false

proc run*(cmd: string, timeoutSec = 4): tuple[output: string, exitCode: int] =
  ## Run a shell command, capture merged output, enforce a soft timeout.
  let t = if timeoutSec > 0: timeoutSec else: 4
  if which("timeout"):
    result = execCmdEx("timeout " & $t & " " & cmd)
  else:
    result = execCmdEx(cmd)

proc existsP*(p: string): bool =
  try: fileExists(p) or dirExists(p)
  except OSError: false

proc readText*(p: string): string =
  try: readFile(p)
  except CatchableError: ""

proc listDir*(p: string): seq[string] =
  ## Non-recursive listing of a directory (full paths).
  result = @[]
  try:
    for kind, path in walkDir(p):
      result.add path
  except CatchableError:
    discard

proc writableByMe*(p: string): bool =
  ## True when `p` exists and the current user can write it (access(2) via
  ## `test -w`). Also covers non-regular files such as sockets and dirs.
  try: run("test -w " & quoteShell(p), 2).exitCode == 0
  except CatchableError: false

proc readableByMe*(p: string): bool =
  ## True when `p` exists and the current user can read it (access(2) via
  ## `test -r`).
  try: run("test -r " & quoteShell(p), 2).exitCode == 0
  except CatchableError: false

proc getHostInfo*(): tuple[hostname, user, kernel: string] =
  result.hostname = run("hostname 2>/dev/null", 2).output.strip()
  if result.hostname.len == 0:
    result.hostname = getEnv("HOSTNAME", "unknown").strip()
  result.user = run("id -un 2>/dev/null", 2).output.strip()
  result.kernel = run("uname -r 2>/dev/null", 2).output.strip()

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

proc add*(r: Registry, id, category, title: string,
          run: proc(opts: Options, rep: Reporter) {.closure.}) =
  r.defs.add CheckDef(id: id, category: category, title: title, run: run)

# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

proc newReporter*(): Reporter =
  Reporter(started: now())

proc addFinding*(rep: Reporter, id, category, title, detail: string,
                 severity: Severity, refs: seq[string] = @[]) =
  rep.findings.add Finding(id: id, category: category, title: title,
                           detail: detail, severity: severity, refs: refs)

proc severityCounts*(rep: Reporter): CountTable[Severity] =
  result = initCountTable[Severity]()
  for f in rep.findings:
    result.inc f.severity

proc sortFindings*(rep: Reporter) =
  rep.findings.sort(proc(a, b: Finding): int =
    result = cmp(severityOrder(b.severity), severityOrder(a.severity))
    if result == 0: result = cmp(a.category, b.category)
    if result == 0: result = cmp(a.title, b.title))

# ---------------------------------------------------------------------------
# Console rendering
# ---------------------------------------------------------------------------

proc bannerText*(): string =
  let w = 68
  let top = "╔" & "═".repeat(w - 2) & "╗"
  let bot = "╚" & "═".repeat(w - 2) & "╝"
  var lines = @[top]
  lines.add "║ " & toolName & " v" & version & " ".repeat(w - toolName.len - version.len - 8) & "║"
  lines.add "║ Linux privilege escalation discovery & exploitation".alignLeft(w - 2) & "║"
  lines.add bot
  result = lines.join("\n")

proc indentBlock*(text: string; spaces: int): string =
  let pad = " ".repeat(spaces)
  result = text.splitLines().mapIt(if it.len == 0: "" else: pad & it).join("\n")

proc renderFinding*(f: Finding; opts: Options; color: bool): string =
  let tag = severityTag(f.severity)
  let tagColored = paint("[" & tag & "]", severityColor(f.severity), color)
  let title = paint(f.title, ansiBold, color)
  var parts = @[tagColored & " " & title]
  if f.detail.len > 0:
    parts.add paint(indentBlock(f.detail, 7), ansiDim, color)
  for r in f.refs:
    parts.add paint(indentBlock("ref: " & r, 7), ansiDim, color)
  result = parts.join("\n")

proc renderHostLine*(opts: Options): string =
  ## One dim "host / user / kernel" line, shown right under the banner.
  let hi = getHostInfo()
  paint("host: " & hi.hostname, ansiDim, opts.color) & "   " &
  paint("user: " & hi.user, ansiDim, opts.color) & "   " &
  paint("kernel: " & hi.kernel, ansiDim, opts.color)

proc renderFindings*(rep: Reporter, opts: Options): string =
  ## The findings sections and summary footer, without the banner or host line.
  rep.sortFindings()
  let color = opts.color
  var findings = rep.findings
  if opts.quiet:
    findings = findings.filterIt(it.severity in {sevCritical, sevHigh})

  if findings.len == 0:
    return paint("No privileged findings.", ansiGreen, color)

  var lines: seq[string] = @[]

  # Group by category preserving severity order within each group.
  var currentCat = ""
  for f in findings:
    if f.category != currentCat:
      currentCat = f.category
      lines.add ""
      lines.add paint("── " & f.category.toUpperAscii & " " &
                    "─".repeat(max(1, 60 - f.category.len)), ansiMagenta & ansiBold, color)
    lines.add renderFinding(f, opts, color)
    lines.add ""

  # Summary footer.
  let c = rep.severityCounts()
  var sumParts: seq[string] = @[]
  for s in [sevCritical, sevHigh, sevMed, sevLow, sevInfo]:
    let n = c.getOrDefault(s)
    sumParts.add paint($n & " " & $s, severityColor(s), color)
  lines.add paint("─".repeat(68), ansiDim, color)
  lines.add "  " & sumParts.join("  ·  ")
  result = lines.join("\n")

proc render*(rep: Reporter; opts: Options): string =
  ## Build the full human-readable report (banner + host line + findings).
  result = bannerText() & "\n\n" & renderHostLine(opts) & "\n\n" &
           renderFindings(rep, opts)

# ---------------------------------------------------------------------------
# JSON rendering
# ---------------------------------------------------------------------------

proc findingJson*(f: Finding): JsonNode =
  result = newJObject()
  result["id"] = %f.id
  result["category"] = %f.category
  result["severity"] = %($f.severity)
  result["title"] = %f.title
  result["detail"] = %f.detail
  if f.refs.len > 0:
    result["refs"] = %f.refs

proc jsonReport*(rep: Reporter): string =
  rep.sortFindings()
  let hi = getHostInfo()
  let c = rep.severityCounts()
  var j = newJObject()
  j["tool"] = %toolName
  j["version"] = %version
  j["hostname"] = %hi.hostname
  j["user"] = %hi.user
  j["kernel"] = %hi.kernel
  j["timestamp"] = %($rep.started.utc)
  j["summary"] = %*{
    "critical": c.getOrDefault(sevCritical),
    "high": c.getOrDefault(sevHigh),
    "medium": c.getOrDefault(sevMed),
    "low": c.getOrDefault(sevLow),
    "info": c.getOrDefault(sevInfo)
  }
  j["findings"] = %(rep.findings.mapIt(findingJson(it)))
  result = j.pretty()
