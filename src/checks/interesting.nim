## checks/interesting.nim - interesting files (scripts in PATH, logs, backups,
## databases, web roots, hidden files, mail spools, recently-modified files).
##
## Contract: see checks/system.nim for the module conventions.
## Category: "files" (complements checks/files.nim).

import std/[os, strutils]
import ../core

# ---------------------------------------------------------------------------
# Small helpers local to this module
# ---------------------------------------------------------------------------

proc currentUser(): string =
  ## Current login name, for comparing file ownership.
  result = run("id -un 2>/dev/null", 2).output.strip()

# ---------------------------------------------------------------------------
# 1. files.sh_in_path - writable / user-owned .sh scripts on PATH
# ---------------------------------------------------------------------------

proc checkShInPath(opts: Options, rep: Reporter) =
  if not which("find"):
    return
  let me = currentUser()
  let path = getEnv("PATH")
  if path.len == 0:
    return

  var count = 0
  for dir in path.split(':'):
    if count >= 40: break
    if dir.len == 0 or not dirExists(dir):
      continue
    let cmd = "find " & quoteShell(dir) & " -maxdepth 1 -type f -name '*.sh' 2>/dev/null"
    let r = run(cmd, 10)
    for raw in r.output.splitLines():
      if count >= 40: break
      let f = raw.strip()
      if f.len == 0: continue
      let owner = run("stat -c '%U' " & quoteShell(f), 4).output.strip()
      if owner == me and me.len > 0:
        rep.addFinding("files.sh_in_path", "files",
                       "User-owned script in PATH: " & f,
                       f & " is owned by the current user - replace it to hijack " &
                       "execution when it runs with higher privileges.", sevHigh)
        inc count
      elif writableByMe(f):
        rep.addFinding("files.sh_in_path", "files",
                       "Writable script in PATH: " & f,
                       f & " is writable by the current user - inject a payload " &
                       "into a script that may run with higher privileges.", sevMed)
        inc count

# ---------------------------------------------------------------------------
# 2. files.modified_5min - files modified in the last 5 minutes
# ---------------------------------------------------------------------------

proc checkModified5min(opts: Options, rep: Reporter) =
  if not opts.all:
    return
  if not which("find"):
    return

  var count = 0
  # /dev/shm is handled separately because it lives under /dev, which we
  # otherwise exclude as virtual noise.
  for root in ["/", "/home", "/opt", "/var", "/tmp"]:
    if count >= 30: break
    if not dirExists(root): continue
    let cmd = "find " & quoteShell(root) & " -xdev -mmin -5 -type f " &
      "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null"
    let r = run(cmd, 15)
    for raw in r.output.splitLines():
      if count >= 30: break
      let f = raw.strip()
      if f.len == 0: continue
      rep.addFinding("files.modified_5min", "files",
                     "Recently modified file: " & f,
                     f & " was modified in the last 5 minutes - possible recent " &
                     "activity or an active exploit worth investigating.", sevLow)
      inc count

  if count < 30 and dirExists("/dev/shm"):
    let r = run("find /dev/shm -xdev -mmin -5 -type f 2>/dev/null", 15)
    for raw in r.output.splitLines():
      if count >= 30: break
      let f = raw.strip()
      if f.len == 0: continue
      rep.addFinding("files.modified_5min", "files",
                     "Recently modified file: " & f,
                     f & " was modified in the last 5 minutes - possible recent " &
                     "activity or an active exploit worth investigating.", sevLow)
      inc count

# ---------------------------------------------------------------------------
# 3. files.writable_logs - writable log files under /var/log
# ---------------------------------------------------------------------------

proc checkWritableLogs(opts: Options, rep: Reporter) =
  if not which("find"):
    return
  if not dirExists("/var/log"):
    return
  let r = run("find /var/log -type f 2>/dev/null", 15)

  var count = 0
  var checked = 0
  for raw in r.output.splitLines():
    if count >= 30 or checked >= 500: break
    let f = raw.strip()
    if f.len == 0: continue
    inc checked
    if writableByMe(f):
      rep.addFinding("files.writable_logs", "files",
                     "Writable log file: " & f,
                     f & " is writable by the current user - inject forged entries " &
                     "to cover tracks or trigger log-based handlers.", sevMed)
      inc count

# ---------------------------------------------------------------------------
# 4. files.backups - readable backup files
# ---------------------------------------------------------------------------

proc checkBackups(opts: Options, rep: Reporter) =
  if not opts.all: return # loud enumeration; only in comprehensive mode
  if not which("find"):
    return
  # System backup locations are scanned fully; $HOME only shallowly, since
  # deep browser/cache trees (LevelDB `LOG.old`, editor `*~`/`.swp`) are noise.
  let sysCmd = "find /var/backups /etc /root -xdev -type f \\( " &
    "-name '*.bak' -o -name '*.orig' -o -name '*.save' -o -iname '*backup*' \\) 2>/dev/null"
  let optCmd = "find /opt -xdev -maxdepth 2 -type f \\( " &
    "-name '*.bak' -o -name '*.orig' -o -name '*.save' -o -iname '*backup*' \\) 2>/dev/null"
  let homeCmd = "find /home -xdev -maxdepth 3 -type f \\( " &
    "-name '*.bak' -o -name '*.orig' -o -name '*.save' -o -iname '*backup*' \\) 2>/dev/null"

  var count = 0
  for cmd in [sysCmd, optCmd, homeCmd]:
    let r = run(cmd, 15)
    for raw in r.output.splitLines():
      if count >= 30: break
      let f = raw.strip()
      if f.len == 0: continue
      if readableByMe(f):
        rep.addFinding("files.backups", "files",
                       "Readable backup file: " & f,
                       f & " is a readable backup - it may contain credentials, " &
                       "config or source not meant to be exposed.", sevMed)
        inc count

# ---------------------------------------------------------------------------
# 5. files.db - readable database / dump files
# ---------------------------------------------------------------------------

proc checkDb(opts: Options, rep: Reporter) =
  if not opts.all: return # loud enumeration; only in comprehensive mode
  if not which("find"):
    return
  # System/app roots are scanned fully; $HOME shallowly with browser/cache
  # profiles excluded, since Chromium/Electron SQLite files are pure noise.
  let sysCmd = "find /var/www /srv /root /var/backups -xdev -type f \\( " &
    "-name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' " &
    "-o -name '*.sql' -o -name '*.dump' \\) 2>/dev/null"
  let optCmd = "find /opt -xdev -maxdepth 3 -type f \\( " &
    "-name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' " &
    "-o -name '*.sql' -o -name '*.dump' \\) 2>/dev/null"
  let homeCmd = "find /home -xdev -maxdepth 4 -type f \\( " &
    "-name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' " &
    "-o -name '*.sql' -o -name '*.dump' \\) " &
    "! -path '*/.BurpSuite/*' ! -path '*/.mozilla/*' ! -path '*/.cache/*' " &
    "! -path '*/.config/google-chrome/*' ! -path '*/.config/chromium/*' " &
    "! -path '*/.config/BraveSoftware/*' ! -path '*/.config/discord/*' 2>/dev/null"

  var count = 0
  for cmd in [sysCmd, optCmd, homeCmd]:
    let r = run(cmd, 15)
    for raw in r.output.splitLines():
      if count >= 30: break
      let f = raw.strip()
      if f.len == 0: continue
      if readableByMe(f):
        rep.addFinding("files.db", "files",
                       "Readable database file: " & f,
                       f & " is readable by the current user - it may contain " &
                       "credentials, hashes or other sensitive data.", sevLow)
        inc count

# ---------------------------------------------------------------------------
# 6. files.web - readable config files under /var/www
# ---------------------------------------------------------------------------

proc checkWeb(opts: Options, rep: Reporter) =
  if not which("find"):
    return
  if not dirExists("/var/www"):
    return
  let cmd = "find /var/www -xdev -type f \\( -name 'wp-config.php' " &
    "-o -name 'config.php' -o -name '.env' -o -name 'settings*' " &
    "-o -name '*.conf' \\) 2>/dev/null"
  let r = run(cmd, 10)

  var count = 0
  var checked = 0
  for raw in r.output.splitLines():
    if count >= 20 or checked >= 300: break
    let f = raw.strip()
    if f.len == 0: continue
    inc checked
    if readableByMe(f):
      rep.addFinding("files.web", "files",
                     "Readable web config: " & f,
                     f & " is a readable web config file - it may hold database " &
                     "credentials, API keys or session secrets.", sevMed)
      inc count

# ---------------------------------------------------------------------------
# 7. files.hidden - hidden files/dirs in common locations
# ---------------------------------------------------------------------------

proc checkHidden(opts: Options, rep: Reporter) =
  if not opts.all: return # loud enumeration; only in comprehensive mode
  if not which("find"):
    return

  var count = 0
  # Temp dirs are scanned fully (a classic attacker staging ground); the root
  # filesystem and /opt only shallowly to avoid deep /var/lib tool internals.
  for cmd in ["find /tmp /var/tmp /dev/shm -xdev -name '.*' 2>/dev/null",
              "find / -xdev -maxdepth 3 -name '.*' " &
                "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' " &
                "! -path '/home/*' ! -path '/root/*' 2>/dev/null",
              "find /opt -xdev -maxdepth 2 -name '.*' 2>/dev/null"]:
    if count >= 30: break
    let r = run(cmd, 15)
    for raw in r.output.splitLines():
      if count >= 30: break
      let f = raw.strip()
      if f.len == 0: continue
      rep.addFinding("files.hidden", "files",
                     "Hidden item: " & f,
                     f & " is hidden - check for planted tools, staging areas " &
                     "or persistence mechanisms.", sevLow)
      inc count

# ---------------------------------------------------------------------------
# 8. files.mails - readable mail files
# ---------------------------------------------------------------------------

proc checkMails(opts: Options, rep: Reporter) =
  if not opts.all: return # loud enumeration; only in comprehensive mode
  let home = getHomeDir()
  var count = 0

  # A plain mbox file in the home directory.
  let mbox = home / "mbox"
  if fileExists(mbox) and readableByMe(mbox):
    rep.addFinding("files.mails", "files",
                   "Readable mailbox: " & mbox,
                   mbox & " is readable - it may contain credentials or account info.",
                   sevLow)
    inc count

  if not which("find"):
    return

  for dir in ["/var/mail", "/var/spool/mail"]:
    if count >= 20: break
    if not dirExists(dir): continue
    let r = run("find " & quoteShell(dir) & " -type f 2>/dev/null", 10)
    for raw in r.output.splitLines():
      if count >= 20: break
      let f = raw.strip()
      if f.len == 0: continue
      if readableByMe(f):
        rep.addFinding("files.mails", "files",
                       "Readable mail: " & f,
                       f & " is readable - it may contain credentials or account info.",
                       sevLow)
        inc count

  let maildir = home / "Maildir"
  if count < 20 and dirExists(maildir):
    let r = run("find " & quoteShell(maildir) & " -type f 2>/dev/null", 10)
    for raw in r.output.splitLines():
      if count >= 20: break
      let f = raw.strip()
      if f.len == 0: continue
      if readableByMe(f):
        rep.addFinding("files.mails", "files",
                       "Readable mail: " & f,
                       f & " is readable - it may contain credentials or account info.",
                       sevLow)
        inc count

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

proc register*(reg: Registry) =
  reg.add("files.sh_in_path", "files", "Scripts in PATH",
    proc(opts: Options, rep: Reporter) = checkShInPath(opts, rep))
  reg.add("files.modified_5min", "files", "Recently modified files",
    proc(opts: Options, rep: Reporter) = checkModified5min(opts, rep))
  reg.add("files.writable_logs", "files", "Writable log files",
    proc(opts: Options, rep: Reporter) = checkWritableLogs(opts, rep))
  reg.add("files.backups", "files", "Backup files",
    proc(opts: Options, rep: Reporter) = checkBackups(opts, rep))
  reg.add("files.db", "files", "Database files",
    proc(opts: Options, rep: Reporter) = checkDb(opts, rep))
  reg.add("files.web", "files", "Web config files",
    proc(opts: Options, rep: Reporter) = checkWeb(opts, rep))
  reg.add("files.hidden", "files", "Hidden files",
    proc(opts: Options, rep: Reporter) = checkHidden(opts, rep))
  reg.add("files.mails", "files", "Mail files",
    proc(opts: Options, rep: Reporter) = checkMails(opts, rep))
