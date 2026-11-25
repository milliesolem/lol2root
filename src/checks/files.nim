## checks/files.nim - SUID/SGID, writable files/dirs, credentials and interesting files.
##
## Contract: see checks/system.nim for the module conventions.

import ../core
import std/[os, strutils, re]

const
  escNames = [
    "sh", "bash", "dash", "zsh", "ksh", "python", "python2", "python3",
    "perl", "ruby", "php", "node", "find", "vim", "nvim", "nano", "less",
    "more", "awk", "gawk", "cp", "mv", "tar", "systemctl", "pkexec",
    "passwd", "chmod", "chown", "su", "sudo", "mount", "umount", "gdb",
    "strace", "socat", "tmux", "screen", "env", "mail", "man", "nice",
    "ping", "arp", "docker", "lxc", "ionice", "taskset", "custom"
  ]

  criticalFiles = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/crontab"
  ]

  sysDirs = [
    "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
    "/usr/local/sbin", "/lib", "/lib64"
  ]

  historyNames = [
    ".bash_history", ".zsh_history", ".mysql_history", ".psql_history",
    ".python_history", ".node_repl_history"
  ]

let secretPattern = re"(?i)(password|passwd|token|secret|api[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)"

proc isEsc(s: string): bool =
  for n in escNames:
    if s == n: return true
  false

proc statOwner(path: string): string =
  let r = run("stat -c '%U:%G %a' " & quoteShell(path), 4)
  if r.exitCode == 0 and r.output.strip().len > 0:
    result = r.output.strip()

proc isWorldReadable(p: string): bool =
  let r = run("stat -c '%a' " & quoteShell(p), 4)
  if r.exitCode != 0: return false
  let mode = r.output.strip()
  if mode.len == 0: return false
  result = mode[^1] in {'4', '5', '6', '7'}

proc unusualSuidPath(path: string): bool =
  let dir = path.parentDir()
  if dir in ["/tmp", "/var/tmp", "/dev/shm", "/home", "/root"]: return true
  if dir.startsWith("/tmp/") or dir.startsWith("/var/tmp/") or
     dir.startsWith("/dev/shm/") or dir.startsWith("/home/") or
     dir.startsWith("/root/"):
    return true
  false

proc detailWithOwner(path: string): string =
  let o = statOwner(path)
  if o.len > 0: path & " (" & o & ")" else: path

# ---------------------------------------------------------------------------
# 1. SUID binaries
# ---------------------------------------------------------------------------

proc checkSuid(opts: Options, rep: Reporter) =
  let cmd = "find / -xdev -perm -4000 -type f " &
    "! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/snap/*' 2>/dev/null"
  let r = run(cmd, 20)
  var count = 0
  for raw in r.output.splitLines():
    if count >= 60: break
    let path = raw.strip()
    if path.len == 0: continue
    let base = path.extractFilename()
    var sev = sevLow
    if isEsc(base) or isEsc(path):
      sev = sevHigh
    elif writableByMe(path):
      sev = sevHigh
    elif unusualSuidPath(path):
      sev = sevHigh
    rep.addFinding("files.suid", "files", "SUID binary", detailWithOwner(path), sev)
    inc count

# ---------------------------------------------------------------------------
# 2. SGID binaries
# ---------------------------------------------------------------------------

proc checkSgid(opts: Options, rep: Reporter) =
  let r = run("find / -xdev -perm -2000 -type f 2>/dev/null", 20)
  var count = 0
  for raw in r.output.splitLines():
    if count >= 30: break
    let path = raw.strip()
    if path.len == 0: continue
    let base = path.extractFilename()
    let writable = writableByMe(path)
    if not (writable or isEsc(base) or isEsc(path)): continue
    let sev = if writable: sevMed else: sevLow
    rep.addFinding("files.sgid", "files", "SGID binary", detailWithOwner(path), sev)
    inc count

# ---------------------------------------------------------------------------
# 3. Writable files and directories
# ---------------------------------------------------------------------------

proc writableCriticalDetail(path: string): string =
  case path
  of "/etc/passwd":
    "/etc/passwd is writable - append a UID 0 account or give your user UID 0."
  of "/etc/shadow":
    "/etc/shadow is writable - read or replace the root password hash."
  of "/etc/group":
    "/etc/group is writable - add yourself to a privileged group (sudo/wheel)."
  of "/etc/gshadow":
    "/etc/gshadow is writable - add yourself to a privileged group."
  of "/etc/sudoers":
    "/etc/sudoers is writable - add '<user> ALL=(ALL) NOPASSWD: ALL'."
  of "/etc/crontab":
    "/etc/crontab is writable - plant a root cron job."
  else:
    path & " is writable - plant a privileged command."

proc checkWritable(opts: Options, rep: Reporter) =
  # Critical system files writable by the current user.
  for f in criticalFiles:
    if existsP(f) and writableByMe(f):
      rep.addFinding("files.writable", "files", "Writable critical file: " & f,
                     writableCriticalDetail(f), sevCritical)

  # Droppable sudoers and cron fragments.
  for f in listDir("/etc/sudoers.d"):
    if writableByMe(f):
      rep.addFinding("files.writable", "files", "Writable sudoers drop-in: " & f,
                     f & " is writable - drop a file granting NOPASSWD: ALL.", sevCritical)
  for f in listDir("/etc/cron.d"):
    if writableByMe(f):
      rep.addFinding("files.writable", "files", "Writable cron drop-in: " & f,
                     f & " is writable - plant a root cron job.", sevCritical)

  # World-writable files in privileged locations.
  var wwCount = 0
  for dir in sysDirs:
    if wwCount >= 30: break
    if not dirExists(dir): continue
    let cmd = "find " & quoteShell(dir) & " -xdev -maxdepth 3 -perm -002 -type f 2>/dev/null"
    let r = run(cmd, 8)
    for raw in r.output.splitLines():
      if wwCount >= 30: break
      let path = raw.strip()
      if path.len == 0: continue
      rep.addFinding("files.writable", "files", "World-writable file",
                     detailWithOwner(path), sevMed)
      inc wwCount

  # Writable entries on PATH.
  for entry in getEnv("PATH").split(':'):
    if entry.len == 0: continue
    if dirExists(entry) and writableByMe(entry):
      rep.addFinding("files.writable", "files", "Writable PATH directory: " & entry,
                     entry & " is writable - plant a malicious binary ahead of a trusted one (PATH hijack).",
                     sevHigh)

# ---------------------------------------------------------------------------
# 4. Credentials and interesting files
# ---------------------------------------------------------------------------

proc checkCredentials(opts: Options, rep: Reporter) =
  # Readable shadow file.
  if existsP("/etc/shadow") and readableByMe("/etc/shadow"):
    rep.addFinding("files.credentials", "files", "Readable /etc/shadow",
                   "/etc/shadow is readable by this user - crack root hashes offline.",
                   sevCritical)

  # Readable SSH private keys.
  let home = getHomeDir()
  for dir in [home & ".ssh", "/root/.ssh"]:
    for f in listDir(dir):
      let name = f.extractFilename()
      if name.startsWith("id_") and not name.endsWith(".pub") and isWorldReadable(f):
        rep.addFinding("files.credentials", "files", "World-readable SSH private key: " & f,
                       f, sevHigh)
  for f in listDir("/etc/ssh"):
    let name = f.extractFilename()
    if name.startsWith("ssh_host_") and name.endsWith("_key") and isWorldReadable(f):
      rep.addFinding("files.credentials", "files", "World-readable SSH host key: " & f,
                     f, sevHigh)

  # Credentials in shell history files.
  for dir in [home, "/root"]:
    for h in historyNames:
      let f = dir / h
      if not existsP(f): continue
      let content = readText(f)
      if content.contains(secretPattern):
        rep.addFinding("files.credentials", "files",
                       "Credentials in history file: " & f, f, sevMed)

  # Deep secret scan (only when requested).
  if opts.all:
    let cmd = "grep -RInE 'password|passwd|secret|api[_-]?key|token|BEGIN [A-Z ]*PRIVATE KEY' " &
      "/home /opt /var/www /tmp /var/tmp 2>/dev/null | head -200"
    let r = run(cmd, 30)
    var seen: seq[string] = @[]
    var count = 0
    for raw in r.output.splitLines():
      if count >= 40: break
      let line = raw.strip()
      if line.len == 0: continue
      let idx = line.find(':')
      if idx <= 0: continue
      let path = line[0 ..< idx]
      if seen.contains(path): continue
      seen.add path
      var detail = line
      if detail.len > 300: detail = detail[0 ..< 300] & "..."
      rep.addFinding("files.credentials", "files",
                     "Possible secret in file: " & path, detail, sevMed)
      inc count

# ---------------------------------------------------------------------------

proc register*(reg: Registry) =
  reg.add("files.suid", "files", "SUID binaries",
    proc(opts: Options, rep: Reporter) = checkSuid(opts, rep))
  reg.add("files.sgid", "files", "SGID binaries",
    proc(opts: Options, rep: Reporter) = checkSgid(opts, rep))
  reg.add("files.writable", "files", "Writable files & PATH",
    proc(opts: Options, rep: Reporter) = checkWritable(opts, rep))
  reg.add("files.credentials", "files", "Credentials & secrets",
    proc(opts: Options, rep: Reporter) = checkCredentials(opts, rep))
