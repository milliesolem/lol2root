## checks/system.nim - OS, users, groups, environment, PATH and sudo.
##
## Contract for this module:
##   export proc register*(reg: Registry)
## and inside register() add every check with reg.add(id, category, title, proc).
##
## Finding conventions:
##   - Only add a Finding when something is actually notable; benign state is
##     silent (this is the "no noise" guarantee).
##   - severity: sevCritical (immediate root path), sevHigh (very likely),
##     sevMed (needs a condition), sevLow (informational lead), sevInfo (context).
##   - Put the actionable detail in `detail` and supporting URLs in `refs`.

import std/[os, strutils]
import ../core

# ---------------------------------------------------------------------------
# Small helpers local to this module
# ---------------------------------------------------------------------------

proc isLoginShell*(shell: string): bool =
  ## True for interactive shells (last path component is a known login shell).
  let base = shell.split('/')[^1].toLowerAscii()
  result = base in ["sh", "bash", "dash", "zsh", "ksh"]

proc stripQuotes*(s: string): string =
  ## Remove a single pair of matching double/single quotes if present.
  if s.len >= 2 and ((s[0] == '"' and s[^1] == '"') or
                     (s[0] == '\'' and s[^1] == '\'')):
    result = s[1 .. ^2]
  else:
    result = s

proc isNameChar(c: char): bool =
  ## ASCII letter or digit, used to detect keyword boundaries.
  (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9')

proc containsKeyword*(s, kw: string): bool =
  ## Word-boundary match: "KEY" must not match inside "KEYPRESS", "MONKEY", ...
  if s.len < kw.len:
    return false
  for i in 0 .. (s.len - kw.len):
    var m = true
    for j in 0 ..< kw.len:
      if s[i + j] != kw[j]:
        m = false
        break
    if m:
      let beforeOk = i == 0 or not isNameChar(s[i - 1])
      let afterOk = i + kw.len == s.len or not isNameChar(s[i + kw.len])
      if beforeOk and afterOk:
        return true
  return false

# ---------------------------------------------------------------------------
# 1. system.os - running user and OS identity (single info finding)
# ---------------------------------------------------------------------------

proc checkOs(opts: Options, rep: Reporter) =
  let uidRes = run("id -u")
  let uid = uidRes.output.strip()
  if uid == "0":
    rep.addFinding("system.os", "system", "Running as root",
                   "uid: " & uid, sevInfo)
    return

  # Not root: report the distro pretty name when it is available.
  let osRelease = readText("/etc/os-release")
  var pretty = ""
  for line in osRelease.splitLines():
    if line.startsWith("PRETTY_NAME="):
      pretty = stripQuotes(line["PRETTY_NAME=".len .. ^1].strip())
      break
  if pretty.len > 0:
    rep.addFinding("system.os", "system", "Operating system", pretty, sevInfo)

# ---------------------------------------------------------------------------
# 2. system.users - duplicate UID 0 accounts and login-shell users
# ---------------------------------------------------------------------------

proc checkUsers(opts: Options, rep: Reporter) =
  let passwd = readText("/etc/passwd")
  if passwd.len == 0:
    return

  var loginUsers: seq[string] = @[]
  for line in passwd.splitLines():
    if line.len == 0 or line.startsWith("#"):
      continue
    let fields = line.split(':')
    if fields.len < 7:
      continue
    let username = fields[0]
    let shell = fields[6]
    var uid = -1
    try:
      uid = parseInt(fields[2])
    except ValueError:
      continue

    # Any account besides root with uid 0 is a full-root backdoor.
    if uid == 0 and username != "root":
      rep.addFinding("system.users", "system",
                     "Duplicate UID 0 account: " & username,
                     "duplicate UID 0 account", sevHigh)

    # Collect interactive users (uid != 0) as a single low-severity lead.
    if uid != 0 and isLoginShell(shell):
      loginUsers.add username

  if loginUsers.len > 0:
    var detail = ""
    for i in 0 ..< loginUsers.len:
      if i >= 10:
        break
      if detail.len > 0:
        detail &= ", "
      detail &= loginUsers[i]
    if loginUsers.len > 10:
      detail &= " (+" & $(loginUsers.len - 10) & " more)"
    rep.addFinding("system.users", "system",
                   "Users with a login shell", detail, sevLow)

# ---------------------------------------------------------------------------
# 3. system.groups - escalation-relevant group memberships
# ---------------------------------------------------------------------------

proc groupSeverity*(g: string): Severity =
  case g
  of "docker", "lxd":
    sevHigh
  of "wheel", "sudo", "adm", "root":
    sevMed
  of "shadow", "disk", "video", "cdrom", "kvm", "vboxusers", "libvirt":
    sevLow
  else:
    sevInfo # not notable; caller skips it

proc groupHint(g: string): string =
  case g
  of "docker":
    "docker group allows mounting the host filesystem inside a container (container escape)."
  of "lxd":
    "lxd group allows creating privileged containers that mount the host root filesystem."
  of "wheel":
    "wheel members can usually use su or sudo to become root."
  of "sudo":
    "sudo group members are granted sudo access."
  of "adm":
    "adm group can read logs under /var/log, which may contain credentials."
  of "root":
    "membership in the root group (gid 0) may grant access to group-writable root-owned files."
  of "shadow":
    "shadow group can read /etc/shadow (password hashes)."
  of "disk":
    "disk group allows raw disk read/write (read or overwrite the whole disk)."
  of "video":
    "video group grants framebuffer/DRM device access; a useful kernel attack surface."
  of "cdrom":
    "cdrom group allows mounting removable media."
  of "kvm":
    "kvm group grants /dev/kvm access; potential guest-to-host escape surface."
  of "vboxusers":
    "vboxusers group grants VirtualBox device access; potential VM escape."
  of "libvirt":
    "libvirt group allows managing VMs and can lead to host compromise."
  else:
    ""

proc checkGroups(opts: Options, rep: Reporter) =
  let res = run("id -Gn")
  let output = res.output.strip()
  if output.len == 0:
    return
  for g in output.split():
    let sev = groupSeverity(g)
    if sev == sevInfo:
      continue
    rep.addFinding("system.groups", "system",
                   "User is in group: " & g, groupHint(g), sev)

# ---------------------------------------------------------------------------
# 4. system.env - secret-like environment variables
# ---------------------------------------------------------------------------

proc checkEnv(opts: Options, rep: Reporter) =
  let res = run("env")
  let output = res.output
  if output.len == 0:
    return

  # Generic keywords are matched on word boundaries so "KEY" does not fire on
  # benign names like UPDATE_PROMPT_ON_KEYPRESS. The full-name list catches
  # composite secret variables that no single keyword covers (e.g. DOCKER_AUTH).
  const keywords = ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASS", "CRED"]
  const fullNames = ["PRIVATE_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                     "AWS_SESSION_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
                     "NPM_TOKEN", "GITHUB_TOKEN", "DOCKER_AUTH"]
  const prefixes = ["AZURE_", "GCP_"]

  for line in output.splitLines():
    if line.len == 0:
      continue
    let eq = line.find('=')
    if eq <= 0:
      continue
    let name = line[0 ..< eq]
    let value = line[eq + 1 .. ^1]

    let up = name.toUpperAscii()
    var matched = false
    for k in keywords:
      if containsKeyword(up, k):
        matched = true
        break
    if not matched:
      for n in fullNames:
        if up.contains(n):
          matched = true
          break
    if not matched:
      for p in prefixes:
        if up.startsWith(p):
          matched = true
          break

    if matched:
      rep.addFinding("system.env", "system", name, name & "=" & value, sevMed)

# ---------------------------------------------------------------------------
# 5. system.path - writable or relative PATH entries
# ---------------------------------------------------------------------------

proc checkPath(opts: Options, rep: Reporter) =
  let path = getEnv("PATH")
  if path.len == 0:
    return

  let entries = path.split(':')
  var usrBinIdx = -1
  for i, e in entries:
    if e == "/usr/bin":
      usrBinIdx = i
      break

  var bad: seq[string] = @[]
  for i, e in entries:
    if e.len == 0 or e == "." or not e.startsWith("/"):
      bad.add(if e.len == 0: "(empty)" else: e)
      continue

    # A directory we can write to lets us shadow or inject executables.
    if writableByMe(e):
      var detail = "writable directory on PATH"
      if usrBinIdx >= 0 and i < usrBinIdx:
        detail &= "\nappears before /usr/bin"
      rep.addFinding("system.path", "system",
                     "Writable PATH directory: " & e, detail, sevHigh)

  if bad.len > 0:
    rep.addFinding("system.path", "system",
                   "Relative or empty PATH entries", bad.join(", "), sevMed)

# ---------------------------------------------------------------------------
# 6. system.sudo - passwordless sudo and writable sudoers files
# ---------------------------------------------------------------------------

proc checkSudo(opts: Options, rep: Reporter) =
  # Writable sudoers configuration is a privilege escalation on its own,
  # independent of whether `sudo -n -l` can list anything.
  if existsP("/etc/sudoers"):
    if writableByMe("/etc/sudoers"):
      rep.addFinding("system.sudo", "system", "Writable /etc/sudoers",
                     "A writable sudoers file lets you add a NOPASSWD root rule.", sevCritical)
  for f in listDir("/etc/sudoers.d"):
    if writableByMe(f):
      rep.addFinding("system.sudo", "system", "Writable sudoers file: " & f,
                     "A writable sudoers.d file lets you add a NOPASSWD root rule.", sevCritical)

  if not which("sudo"):
    return

  let res = run("sudo -n -l 2>/dev/null")
  if res.exitCode != 0 or res.output.strip().len == 0:
    return

  var passwordlessRoot = false
  var sudoAllPassword = false
  var nopasswdCommands: seq[string] = @[]

  for rawLine in res.output.splitLines():
    let line = rawLine.strip()
    if line.len == 0:
      continue

    if line.contains("(ALL) NOPASSWD: ALL") or
       line.contains("(root) NOPASSWD: ALL") or
       line.contains("(ALL : ALL) NOPASSWD: ALL"):
      passwordlessRoot = true
    elif (line.contains("(ALL) ALL") or
          line.contains("(root) ALL") or
          line.contains("(ALL : ALL) ALL")) and not line.contains("NOPASSWD"):
      sudoAllPassword = true

    if line.contains("NOPASSWD:"):
      let idx = line.find("NOPASSWD:")
      let cmdPart = line[idx + "NOPASSWD:".len .. ^1].strip()
      if cmdPart.len > 0 and cmdPart != "ALL":
        nopasswdCommands.add cmdPart

  if passwordlessRoot:
    rep.addFinding("system.sudo", "system", "sudo gives passwordless root",
                   "The current user can run any command as root without a password.", sevCritical)
  if sudoAllPassword:
    rep.addFinding("system.sudo", "system", "sudo ALL with password",
                   "The current user can run any command as root; only the user's password is needed.", sevMed)
  if nopasswdCommands.len > 0:
    rep.addFinding("system.sudo", "system",
                   "Passwordless sudo for specific commands",
                   nopasswdCommands.join("\n"), sevHigh)

# ---------------------------------------------------------------------------
# 7. system.caps - file capabilities on the whole filesystem
# ---------------------------------------------------------------------------

proc capSeverity*(caps: string): Severity =
  const highCaps = ["cap_setuid", "cap_setgid", "cap_dac_override",
                    "cap_dac_read_search", "cap_sys_admin", "cap_sys_module",
                    "cap_sys_ptrace", "cap_sys_chroot"]
  for c in highCaps:
    if caps.contains(c):
      return sevHigh
  if caps.contains("cap_net_admin") or caps.contains("cap_net_raw"):
    return sevMed
  return sevInfo # not notable

proc checkCaps(opts: Options, rep: Reporter) =
  if not which("getcap"):
    return
  let res = run("getcap -r / 2>/dev/null", 15)
  let output = res.output.strip()
  if output.len == 0:
    return

  for rawLine in output.splitLines():
    let line = rawLine.strip()
    if line.len == 0:
      continue
    let sp = line.find(' ')
    if sp < 0:
      continue
    let path = line[0 ..< sp].strip()
    let caps = line[sp .. ^1].strip()
    if path.len == 0 or caps.len == 0:
      continue

    let sev = capSeverity(caps)
    if sev == sevHigh or sev == sevMed:
      rep.addFinding("system.caps", "system", path, caps, sev)

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

proc register*(reg: Registry) =
  reg.add("system.os", "system", "OS information", checkOs)
  reg.add("system.users", "system", "Users", checkUsers)
  reg.add("system.groups", "system", "Groups", checkGroups)
  reg.add("system.env", "system", "Environment", checkEnv)
  reg.add("system.path", "system", "PATH", checkPath)
  reg.add("system.sudo", "system", "Sudo", checkSudo)
  reg.add("system.caps", "system", "File capabilities", checkCaps)
