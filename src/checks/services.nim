## checks/services.nim - cron jobs, systemd units/timers, running processes.
##
## Contract: see checks/system.nim for the module conventions.

import std/[os, strutils]
import ../core

const cat = "services"

# ---------------------------------------------------------------------------
# 1. cron jobs
# ---------------------------------------------------------------------------

proc extractCronCommand(line: string; hasUserField: bool): string =
  ## Return the absolute command path referenced by a cron schedule line, or ""
  ## when the line has no such path (comments, env assignments, run-parts, ...).
  let t = line.strip()
  if t.len == 0 or t[0] == '#':
    return ""
  let tokens = t.splitWhitespace()
  if tokens.len == 0:
    return ""
  # Environment variable assignment lines (SHELL=..., MAILTO=..., PATH=...).
  if '=' in tokens[0]:
    return ""
  # run-parts lines point at the .d directories, which are already covered as
  # cron source files; skip them to avoid double counting.
  for tok in tokens:
    if tok == "run-parts" or tok.endsWith("/run-parts"):
      return ""
  # Locate the command: skip the schedule (5 fields, or 1 for @spec) and, for
  # system crontab / cron.d formats, the username field.
  var i = 0
  if tokens[0].startsWith("@"):
    i = 1
    if hasUserField and i < tokens.len: inc i
  else:
    i = 5
    if hasUserField: inc i
  if i >= tokens.len:
    return ""
  let cmd = tokens[i]
  if cmd.startsWith("/"):
    return cmd
  return ""

proc checkCron(opts: Options, rep: Reporter) =
  const id = "services.cron"

  # Source files whose content root will run (writability here is the critical
  # case). Includes the .d script directories and per-user crontab spools.
  var sourceFiles: seq[string] = @["/etc/crontab"]
  for d in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
            "/etc/cron.weekly", "/etc/cron.monthly",
            "/var/spool/cron/crontabs", "/var/spool/cron"]:
    for p in listDir(d):
      sourceFiles.add p

  var emitted = 0
  template emit(id0, title0, detail0, sev0: untyped) =
    if emitted < 50:
      rep.addFinding(id0, cat, title0, detail0, sev0)
      inc emitted

  # (a) writable root cron source file.
  for f in sourceFiles:
    if writableByMe(f):
      emit(id, f, "writable root cron source", sevCritical)
      if emitted >= 50: return

  # (b) writable scripts referenced by cron lines.
  type CronSrc = tuple[content: string, hasUser: bool]
  var sources: seq[CronSrc] = @[]
  let userCrontab = run("crontab -l 2>/dev/null", 4).output
  if userCrontab.strip().len > 0:
    sources.add (content: userCrontab, hasUser: false)
  sources.add (content: readText("/etc/crontab"), hasUser: true)
  for f in listDir("/etc/cron.d"):
    sources.add (content: readText(f), hasUser: true)
  for f in listDir("/var/spool/cron/crontabs"):
    sources.add (content: readText(f), hasUser: false)
  for f in listDir("/var/spool/cron"):
    sources.add (content: readText(f), hasUser: false)

  var checked: seq[string] = @[]
  for src in sources:
    for line in src.content.splitLines():
      if emitted >= 50: return
      let cmd = extractCronCommand(line, src.hasUser)
      if cmd.len == 0: continue
      if cmd in checked: continue
      checked.add cmd
      if writableByMe(cmd):
        emit(id, cmd, "root cron executes writable script", sevHigh)

# ---------------------------------------------------------------------------
# 2. systemd units
# ---------------------------------------------------------------------------

proc unitRunsAsRoot(content: string): bool =
  ## True when the unit has no `User=` line, or `User=root` (i.e. runs as root).
  for line in content.splitLines():
    let t = line.strip()
    if t.startsWith("User="):
      let v = t[5 .. ^1].strip().splitWhitespace()
      return v.len > 0 and v[0] == "root"
  true

proc extractExecPaths(content: string): seq[string] =
  ## Collect absolute command paths from ExecStart/ExecStartPre/ExecStartPost.
  result = @[]
  for line in content.splitLines():
    let t = line.strip()
    if not (t.startsWith("ExecStart=") or t.startsWith("ExecStartPre=") or
            t.startsWith("ExecStartPost=")):
      continue
    let eq = t.find('=')
    if eq < 0: continue
    var val = t[eq + 1 .. ^1].strip()
    # Drop executable path prefixes: @ - + ! $
    while val.len > 0 and val[0] in {'@', '-', '+', '!', '$'}:
      val = val[1 .. ^1].strip()
    let tok = val.splitWhitespace()
    if tok.len == 0: continue
    if tok[0].startsWith("/"):
      result.add tok[0]

proc checkSystemd(opts: Options, rep: Reporter) =
  const id = "services.systemd"
  let r = run("find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system " &
              "-maxdepth 1 -name '*.service' 2>/dev/null", 20)
  var emitted = 0
  var seen: seq[string] = @[]

  for raw in r.output.splitLines():
    if emitted >= 40: break
    let f = raw.strip()
    if f.len == 0 or not existsP(f): continue
    if writableByMe(f):
      rep.addFinding(id, cat, f, "writable systemd unit file", sevCritical)
      inc emitted
      continue
    let content = readText(f)
    if content.len == 0: continue
    if not unitRunsAsRoot(content): continue
    for exe in extractExecPaths(content):
      if emitted >= 40: break
      if exe in seen: continue
      seen.add exe
      if writableByMe(exe):
        rep.addFinding(id, cat, exe,
                       "root systemd service executes writable binary", sevHigh)
        inc emitted

# ---------------------------------------------------------------------------
# 3. systemd timers
# ---------------------------------------------------------------------------

proc checkTimers(opts: Options, rep: Reporter) =
  if not opts.all:
    return
  let output = run("systemctl list-timers --all --no-pager 2>/dev/null", 10).output
  if output.strip().len == 0:
    return
  var lines = output.splitLines()
  # Count entries that reference a .timer unit.
  var count = 0
  for l in lines:
    if l.contains(".timer"): inc count
  if count == 0:
    return

  var shown: seq[string] = @[]
  var truncated = false
  for l in lines:
    if shown.len >= 20:
      truncated = true
      break
    shown.add l

  var detail = $count & " timer" & (if count == 1: "" else: "s") & " found:\n"
  detail.add shown.join("\n")
  if truncated:
    detail.add "\n… (" & $lines.len & " lines total, truncated)"

  rep.addFinding("services.timers", cat, "Systemd timers", detail, sevInfo)

# ---------------------------------------------------------------------------
# 4. running processes
# ---------------------------------------------------------------------------

proc parseProcLine(line: string; pidFirst: bool): tuple[pid: int, user, args: string] =
  ## Parse one line of `ps`. pidFirst = `ps -eo pid,user,args` layout.
  result = (pid: -1, user: "", args: "")
  let t = line.strip()
  if t.len == 0:
    return
  if pidFirst:
    let parts = t.splitWhitespace(maxsplit = 2)
    if parts.len < 3: return
    try:
      result.pid = parseInt(parts[0])
    except ValueError:
      return
    result.user = parts[1]
    result.args = parts[2]
  else:
    # `ps aux`: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
    let parts = t.splitWhitespace(maxsplit = 10)
    if parts.len < 11: return
    try:
      result.pid = parseInt(parts[1])
    except ValueError:
      return
    result.user = parts[0]
    result.args = parts[10]

proc checkProcesses(opts: Options, rep: Reporter) =
  const id = "services.processes"
  var output = run("ps -eo pid,user,args --no-headers 2>/dev/null", 5).output
  var pidFirst = true
  if output.strip().len == 0:
    output = run("ps aux 2>/dev/null", 5).output
    pidFirst = false
  if output.strip().len == 0:
    return

  var emitted = 0
  var seen: seq[string] = @[]
  for line in output.splitLines():
    if emitted >= 30: break
    let (pid, user, args) = parseProcLine(line, pidFirst)
    if pid < 0: continue
    if user != "root" and user != "0": continue

    let rl = run("readlink /proc/" & $pid & "/exe 2>/dev/null", 2)
    if rl.exitCode != 0: continue
    let exe = rl.output.strip()
    if exe.len == 0: continue
    if exe in seen: continue
    seen.add exe
    if writableByMe(exe):
      rep.addFinding(id, cat, exe, "pid " & $pid & ": " & args, sevHigh)
      inc emitted

# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------

proc register*(reg: Registry) =
  reg.add("services.cron", cat, "Cron jobs", checkCron)
  reg.add("services.systemd", cat, "Systemd units", checkSystemd)
  reg.add("services.timers", cat, "Systemd timers", checkTimers)
  reg.add("services.processes", cat, "Running processes", checkProcesses)
