## checks/software.nim - installed software and known-vulnerable versions.
##
## Contract: see checks/system.nim for the module conventions.
## Category: "software".

import std/strutils
import ../core

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

type
  SVer = tuple[maj, min, pat: int]

proc parseVersion(s: string): SVer =
  ## Extract the first "M[.m[.p]]" digit sequence from `s` (e.g. "1.9.5p2").
  ## A patch-level suffix such as "p2" is intentionally ignored: callers
  ## compare numeric major.minor.patch only.
  result = (0, 0, 0)
  var i = 0
  while i < s.len and s[i] notin {'0'..'9'}:
    inc i
  if i >= s.len:
    return
  var nums: seq[int] = @[]
  while i < s.len and s[i] in {'0'..'9'}:
    var v = 0
    while i < s.len and s[i] in {'0'..'9'}:
      v = v * 10 + (ord(s[i]) - ord('0'))
      inc i
    nums.add v
    if i < s.len and s[i] == '.':
      inc i
    else:
      break
  if nums.len > 0: result.maj = nums[0]
  if nums.len > 1: result.min = nums[1]
  if nums.len > 2: result.pat = nums[2]

proc versionCmp(a, b: SVer): int =
  if a.maj != b.maj: return cmp(a.maj, b.maj)
  if a.min != b.min: return cmp(a.min, b.min)
  cmp(a.pat, b.pat)

# ---------------------------------------------------------------------------
# 1. software.sudo - sudo version + Baron Samedit (CVE-2021-3156)
# ---------------------------------------------------------------------------

proc checkSudoVersion(opts: Options, rep: Reporter) =
  if not which("sudo"):
    return
  let res = run("sudo -V 2>/dev/null", 4)
  if res.output.len == 0:
    return
  var versionStr = ""
  for line in res.output.splitLines():
    let low = line.toLowerAscii()
    let idx = low.find("version")
    if idx >= 0:
      versionStr = line.substr(idx + "version".len).strip()
      break
  if versionStr.len == 0:
    versionStr = res.output.strip()
  let v = parseVersion(versionStr)
  if v.maj == 0:
    return
  # CVE-2021-3156 affects 1.8.2 through 1.9.5p1 (fixed in 1.9.5p2). We ignore
  # the `pN` suffix, so flag only versions strictly below 1.9.5 to avoid
  # flagging the fixed 1.9.5p2 release.
  if versionCmp(v, (maj: 1, min: 8, pat: 2)) >= 0 and
      versionCmp(v, (maj: 1, min: 9, pat: 5)) < 0:
    rep.addFinding("software.sudo", "software",
      "Sudo vulnerable to Baron Samedit (CVE-2021-3156)",
      "sudo " & versionStr, sevHigh,
      @["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"])
  else:
    rep.addFinding("software.sudo", "software", "Sudo version",
      versionStr, sevLow)

# ---------------------------------------------------------------------------
# 2. software.doas - doas.conf rules
# ---------------------------------------------------------------------------

proc checkDoas(opts: Options, rep: Reporter) =
  if not which("doas"):
    return
  if existsP("/etc/doas.conf") and writableByMe("/etc/doas.conf"):
    rep.addFinding("software.doas", "software", "Writable /etc/doas.conf",
      "A writable doas.conf lets you add a nopass root rule.", sevCritical)
  for line in readText("/etc/doas.conf").splitLines():
    let ln = line.strip()
    if ln.len == 0 or ln.startsWith("#"):
      continue
    let low = ln.toLowerAscii()
    if low.contains("permit") and low.contains("nopass") and
        (low.contains("root") or low.contains("wheel")):
      rep.addFinding("software.doas", "software", "Passwordless doas rule",
        ln, sevHigh)

# ---------------------------------------------------------------------------
# 3. software.pkexec - PwnKit (CVE-2021-4034)
# ---------------------------------------------------------------------------

proc checkPkexec(opts: Options, rep: Reporter) =
  if not which("pkexec"):
    return
  let res = run("pkexec --version 2>/dev/null", 4)
  var detail = "pkexec present (PwnKit CVE-2021-4034 applies to many versions)"
  if res.exitCode == 0 and res.output.strip().len > 0:
    detail &= "\nversion: " & res.output.strip()
  rep.addFinding("software.pkexec", "software", "pkexec present", detail,
    sevLow, @["https://nvd.nist.gov/vuln/detail/CVE-2021-4034"])

# ---------------------------------------------------------------------------
# 4. software.gtfobins - GTFO-relevant binaries
# ---------------------------------------------------------------------------

proc checkGtfobins(opts: Options, rep: Reporter) =
  const bins = ["python3", "python", "perl", "ruby", "php", "node", "find",
    "vim", "nvim", "nano", "less", "more", "awk", "gawk", "sed", "tar", "cp",
    "mv", "git", "tmux", "screen", "socat", "nc", "ncat", "env", "busybox",
    "docker", "lxc", "ssh", "scp", "rsync", "curl", "wget", "dd", "base64",
    "openssl", "systemctl", "apt-get", "apt", "pip", "pip3", "npm"]
  var found: seq[string] = @[]
  for b in bins:
    if which(b):
      found.add b
  if found.len == 0:
    return
  var detail: string
  if found.len > 20:
    detail = found[0 .. 19].join(", ") & " (+" & $(found.len - 20) & " more)"
  else:
    detail = found.join(", ")
  rep.addFinding("software.gtfobins", "software", "GTFO-relevant binaries",
    detail, sevInfo)

# ---------------------------------------------------------------------------
# 5. software.tools - escalation/dev tools
# ---------------------------------------------------------------------------

proc checkTools(opts: Options, rep: Reporter) =
  const tools = ["gcc", "cc", "make", "perl", "python3", "curl", "wget", "nc",
    "socat", "nmap", "tcpdump", "xxd", "strings", "strace", "ltrace", "radare2",
    "gdb"]
  var found: seq[string] = @[]
  for t in tools:
    if which(t):
      found.add t
  if found.len == 0:
    return
  rep.addFinding("software.tools", "software", "Escalation/dev tools",
    found.join(", "), sevInfo)

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

proc register*(reg: Registry) =
  reg.add("software.sudo", "software", "Sudo version", checkSudoVersion)
  reg.add("software.doas", "software", "Doas configuration", checkDoas)
  reg.add("software.pkexec", "software", "pkexec", checkPkexec)
  reg.add("software.gtfobins", "software", "GTFO binaries", checkGtfobins)
  reg.add("software.tools", "software", "Escalation tools", checkTools)
