## checks/kernel.nim - kernel version / CVE heuristics and the CopyFail check.
##
## Contract: see checks/system.nim for the module conventions.
##
## This module also exposes `copyfailStatus` so the exploit engine can reuse
## the same detection logic instead of duplicating it.

import std/[os, strutils]
import ../core

type
  KVer* = tuple[maj, min, pat: int]

const
  aeadConfigName = "CONFIG_CRYPTO_USER_API_AEAD"
  # Non-destructive AF_ALG/splice probe, ported from PEASS-ng checkCopyFail.sh.
  # It only creates/removes a temp file and never touches a real file's content.
  copyFailCanRunPy = """import ctypes, os, sys
try:
    if hasattr(os, "splice"):
        sys.exit(0)
    libc = ctypes.CDLL(None, use_errno=True)
    sys.exit(0 if hasattr(libc, "splice") else 1)
except Exception:
    sys.exit(1)
"""
  copyFailProbePy = """import errno, os, signal, socket, struct, sys, tempfile, shutil

try:
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("probe timeout")))
    signal.alarm(10)
except Exception:
    pass

AF_ALG=38
SOCK_SEQPACKET=5
SOL_ALG=279
ALG_SET_KEY=1
ALG_SET_IV=2
ALG_SET_OP=3
ALG_SET_AEAD_ASSOCLEN=4
ALG_SET_AEAD_AUTHSIZE=5
ALG_OP_DECRYPT=0
ALG="authencesn(hmac(sha256),cbc(aes))"
PAGE=4096
TARGET_OFF=16
MARK=b"CF31"

def out(msg, code):
    print(msg, flush=True)
    raise SystemExit(code)

def build_splice():
    if hasattr(os, "splice"):
        def _splice(fd_in, fd_out, length, offset_src=None, offset_dst=None):
            return os.splice(fd_in, fd_out, length, offset_src=offset_src, offset_dst=offset_dst)
        return _splice

    try:
        import ctypes
        libc=ctypes.CDLL(None, use_errno=True)
        splice_fn=libc.splice
        off_t=ctypes.c_longlong
        splice_fn.argtypes=[ctypes.c_int, ctypes.POINTER(off_t), ctypes.c_int, ctypes.POINTER(off_t), ctypes.c_size_t, ctypes.c_uint]
        splice_fn.restype=ctypes.c_ssize_t
    except Exception as e:
        out("PYTHON_UNUSABLE: splice helper is not available (%s)" % e, 1)

    def _splice(fd_in, fd_out, length, offset_src=None, offset_dst=None):
        in_off=off_t(offset_src) if offset_src is not None else None
        out_off=off_t(offset_dst) if offset_dst is not None else None
        n=splice_fn(
            fd_in,
            ctypes.byref(in_off) if in_off is not None else None,
            fd_out,
            ctypes.byref(out_off) if out_off is not None else None,
            length,
            0,
        )
        if n < 0:
            err=ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return n

    return _splice

SPLICE=build_splice()
fd=rfd=wfd=None
op=master=None
td=None

try:
    try:
        master=socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
        master.bind(("aead", ALG))
    except OSError as e:
        out("NOT VULNERABLE: AF_ALG/authencesn is not reachable from this context (%s)" % (e.strerror or e), 0)

    master.setsockopt(SOL_ALG, ALG_SET_KEY, bytes.fromhex("0800010000000010" + "00"*32))
    master.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)
    op,_=master.accept()

    try:
        op.settimeout(3.0)
    except Exception:
        pass

    td=tempfile.mkdtemp(prefix="cf31-check-")
    path=os.path.join(td, "sentinel")
    baseline=b"A"*PAGE

    with open(path, "wb") as f:
        f.write(baseline)

    fd=os.open(path, os.O_RDONLY)
    os.read(fd, PAGE)
    os.lseek(fd, 0, 0)

    cmsgs=[
        (SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
        (SOL_ALG, ALG_SET_IV, struct.pack("I",16)+b"\x00"*16),
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I",8)),
    ]

    op.sendmsg([b"AAAA"+MARK], cmsgs, socket.MSG_MORE)

    rfd,wfd=os.pipe()
    splice_len=TARGET_OFF+len(MARK)

    n=SPLICE(fd, wfd, splice_len, offset_src=0)
    if n != splice_len:
        out("UNKNOWN: short splice file->pipe (%d/%d)" % (n, splice_len), 1)

    n2=SPLICE(rfd, op.fileno(), splice_len)
    if n2 != splice_len:
        out("UNKNOWN: short splice pipe->AF_ALG (%d/%d)" % (n2, splice_len), 1)

    try:
        op.recv(64)
    except OSError as e:
        if e.errno not in (errno.EBADMSG, errno.EINVAL):
            raise
    except TimeoutError:
        out("PYTHON_PROBE_UNKNOWN: recv timed out", 1)

    os.lseek(fd, 0, 0)
    after=os.read(fd, PAGE)

    if after[TARGET_OFF:TARGET_OFF+len(MARK)] == MARK:
        out("VULNERABLE: non-destructive AF_ALG/splice page-cache write triggered", 2)

    if after != baseline:
        out("VULNERABLE: temp-file page cache changed unexpectedly", 2)

    out("NOT VULNERABLE: Python runtime probe left temp-file page cache intact", 0)

except SystemExit:
    raise
except Exception as e:
    out("PYTHON_PROBE_UNKNOWN: %s: %s" % (type(e).__name__, e), 1)
finally:
    try:
        signal.alarm(0)
    except Exception:
        pass

    for x in (fd,rfd,wfd):
        try:
            if x is not None:
                os.close(x)
        except Exception:
            pass

    for s in (op,master):
        try:
            if s is not None:
                s.close()
        except Exception:
            pass

    try:
        if td:
            shutil.rmtree(td)
    except Exception:
        pass
"""

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

proc versionLt*(a, b: KVer): bool =
  if a.maj != b.maj: a.maj < b.maj
  elif a.min != b.min: a.min < b.min
  else: a.pat < b.pat

proc versionGe*(a, b: KVer): bool =
  not versionLt(a, b)

proc parseKernelVersion*(release: string): KVer =
  ## Strip non-numeric prefixes/suffixes and return (maj, min, pat).
  result = (maj: 0, min: 0, pat: 0)
  var t = ""
  for ch in release:
    if ch in {'0'..'9'} or ch == '.':
      t.add ch
    elif t.len > 0:
      break
  if t.len == 0:
    return

  let parts = t.split('.')
  proc num(s: string): int =
    var v = 0
    for ch in s:
      if ch in {'0'..'9'}:
        v = v * 10 + (ord(ch) - ord('0'))
    v
  if parts.len > 0: result.maj = num(parts[0])
  if parts.len > 1: result.min = num(parts[1])
  if parts.len > 2: result.pat = num(parts[2])

proc parseGlibcVersion*(s: string): tuple[maj, min: int] =
  ## First "M.m" decimal pair in `ldd --version` output (the glibc version).
  result = (0, 0)
  var i = 0
  while i < s.len and s[i] notin {'0'..'9'}:
    inc i
  if i >= s.len: return
  var maj = 0
  while i < s.len and s[i] in {'0'..'9'}:
    maj = maj * 10 + (ord(s[i]) - ord('0'))
    inc i
  if i < s.len and s[i] == '.':
    inc i
    var mn = 0
    while i < s.len and s[i] in {'0'..'9'}:
      mn = mn * 10 + (ord(s[i]) - ord('0'))
      inc i
    result = (maj, mn)

# ---------------------------------------------------------------------------
# CopyFail (CVE-2026-31431) detection
# ---------------------------------------------------------------------------

proc isFixedUpstream*(maj, min, pat: int): bool =
  ## Exact fixed-release tuples from PEASS-ng checkCopyFail.sh.
  if maj >= 7:
    return true
  if maj == 6:
    case min
    of 19: return pat >= 12
    of 18: return pat >= 22
    of 12: return pat >= 85
    of 6:  return pat >= 137
    of 1:  return pat >= 170
    else: discard
  elif maj == 5:
    case min
    of 15: return pat >= 204
    of 10: return pat >= 254
    else: discard
  return false

proc findAeadConfigLine*(text: string): string =
  ## Last `CONFIG_CRYPTO_USER_API_AEAD` config line in text ("" if absent).
  result = ""
  for raw in text.splitLines():
    var line = raw.strip()
    if line.startsWith("# "):
      line = line[2..^1]
    if line.startsWith(aeadConfigName):
      let rest = if line.len > aeadConfigName.len: line[aeadConfigName.len..^1] else: ""
      if rest.startsWith("=") or rest.startsWith(" is not set"):
        result = line

proc classifyAeadConfig*(line: string): string =
  if "is not set" in line: "off"
  elif "=y" in line: "builtin"
  elif "=m" in line: "module"
  else: "unknown"

proc detectAeadExposure(release: string): string =
  ## CONFIG_CRYPTO_USER_API_AEAD exposure: off/builtin/module/loaded/reachable/unknown.
  result = "unknown"
  let configFiles = [
    "/proc/config.gz",
    "/boot/config-" & release,
    "/lib/modules/" & release & "/config",
  ]
  for f in configFiles:
    var text = ""
    if f.endsWith(".gz"):
      if which("gzip"):
        text = run("gzip -cd " & quoteShell(f) & " 2>/dev/null", 6).output
    else:
      text = readText(f)
    let line = findAeadConfigLine(text)
    if line.len > 0:
      result = classifyAeadConfig(line)

  if result != "unknown":
    return

  # Fallbacks when no usable kernel config is present.
  if existsP("/sys/module/algif_aead"):
    return "loaded"
  if which("modinfo"):
    let r = run("modinfo algif_aead 2>/dev/null", 4)
    if r.exitCode == 0:
      return "module"
  let found = run("find " & quoteShell("/lib/modules/" & release) &
                  " -name 'algif_aead.ko*' -print 2>/dev/null", 8).output
  if found.strip().len > 0:
    return "module"
  if "authencesn(hmac(sha256),cbc(aes))" in readText("/proc/crypto"):
    return "reachable"

proc pyCanRunProbe(pythonBin: string): bool =
  let r = run(pythonBin & " -c " & quoteShell(copyFailCanRunPy) & " 2>/dev/null", 8)
  r.exitCode == 0

proc runPythonProbe(pythonBin: string): string =
  ## First non-empty probe output line, or "" if the probe could not run.
  result = ""
  let tmp = "/tmp/cf31-probe-" & $getCurrentProcessId() & ".py"
  try:
    writeFile(tmp, copyFailProbePy)
    let r = run(pythonBin & " " & quoteShell(tmp) & " 2>/dev/null", 15)
    for line in r.output.splitLines():
      let l = line.strip()
      if l.len > 0:
        return l
  except CatchableError:
    discard
  finally:
    try: removeFile(tmp)
    except CatchableError: discard

proc copyfailStatus*(opts: Options): tuple[vulnerable: bool, reason: string] =
  ## Determine whether the running kernel is in the CopyFail (CVE-2026-31431)
  ## affected range and exposes the AEAD user API. Prefer the non-destructive
  ## Python runtime probe when available; otherwise fall back to the upstream
  ## fixed-release + AEAD exposure heuristics from PEASS-ng checkCopyFail.sh.
  let sysname = run("uname -s", 2).output.strip()
  if sysname != "Linux":
    return (false, "not Linux")

  let release = run("uname -r", 2).output.strip()
  let v = parseKernelVersion(release)
  if v.maj == 0 and v.min == 0 and v.pat == 0:
    return (false, "could not parse kernel version: " & release)

  if v.maj < 4 or (v.maj == 4 and v.min < 14):
    return (false, "kernel " & release & " predates 4.14")

  if isFixedUpstream(v.maj, v.min, v.pat):
    return (false, "kernel " & release & " is at/after a fixed upstream release")

  let exposure = detectAeadExposure(release)
  if exposure == "off":
    return (false, "AEAD API disabled (CONFIG_CRYPTO_USER_API_AEAD is not set)")

  var heuristicVuln = false
  var heuristicReason = ""
  if exposure == "unknown":
    heuristicReason = "kernel " & release & " is in affected range but AEAD exposure unverified"
  else:
    heuristicVuln = true
    heuristicReason = "kernel " & release & " is in affected range, AEAD user API appears " & exposure

  # Non-destructive runtime probe, when Python can drive splice(). A definitive
  # probe result overrides the heuristic in both directions; an inconclusive one
  # keeps it.
  for py in ["python3", "python"]:
    if which(py) and pyCanRunProbe(py):
      let line = runPythonProbe(py)
      if line.startsWith("VULNERABLE"):
        return (true, line)
      if line.startsWith("NOT VULNERABLE"):
        return (false, line)
      break

  return (heuristicVuln, heuristicReason)

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

proc checkCopyFail(opts: Options, rep: Reporter) =
  let (vuln, reason) = copyfailStatus(opts)
  if vuln:
    rep.addFinding("kernel.copyfail", "kernel", "CopyFail CVE-2026-31431",
                   reason, sevHigh,
                   @["https://nvd.nist.gov/vuln/detail/CVE-2026-31431"])

proc checkCves(opts: Options, rep: Reporter) =
  let release = run("uname -r", 2).output.strip()
  if release.len == 0: return
  let v = parseKernelVersion(release)
  if v.maj == 0: return

  proc addCve(id, title, cve: string) =
    rep.addFinding(id, "kernel", title,
                   "kernel " & release & " is in affected range", sevHigh,
                   @["https://nvd.nist.gov/vuln/detail/" & cve])

  # Dirty COW: fixed in 4.8.3; conservatively flag < 4.8.3 plus all 4.8.x.
  if versionLt(v, (maj: 4, min: 8, pat: 3)) or (v.maj == 4 and v.min == 8):
    addCve("kernel.cve.2016-5195", "Dirty COW CVE-2016-5195", "CVE-2016-5195")

  if versionLt(v, (maj: 4, min: 13, pat: 0)):
    addCve("kernel.cve.2017-1000112", "udp frag offload CVE-2017-1000112", "CVE-2017-1000112")

  if versionGe(v, (maj: 5, min: 8, pat: 0)) and versionLt(v, (maj: 5, min: 16, pat: 11)):
    addCve("kernel.cve.2022-0847", "Dirty Pipe CVE-2022-0847", "CVE-2022-0847")

  if versionGe(v, (maj: 5, min: 12, pat: 0)) and versionLt(v, (maj: 5, min: 19, pat: 0)):
    addCve("kernel.cve.2022-2588", "cls_route use-after-free CVE-2022-2588", "CVE-2022-2588")

  if versionGe(v, (maj: 5, min: 11, pat: 0)) and versionLt(v, (maj: 6, min: 2, pat: 0)):
    addCve("kernel.cve.2023-0386", "overlayfs setuid CVE-2023-0386", "CVE-2023-0386")

  # Looney Tunables is a glibc bug, so gate on the detected glibc version.
  let (gmaj, gmin) = parseGlibcVersion(run("ldd --version 2>/dev/null", 2).output)
  if gmaj == 2 and gmin >= 34 and gmin <= 37:
    addCve("kernel.cve.2023-4911", "Looney Tunables CVE-2023-4911 (glibc)", "CVE-2023-4911")

proc checkUserns(opts: Options, rep: Reporter) =
  var enabled = false
  let clonePath = "/proc/sys/kernel/unprivileged_userns_clone"
  if existsP(clonePath) and readText(clonePath).strip() == "1":
    enabled = true
  if not enabled:
    let nsPath = "/proc/sys/user/max_user_namespaces"
    if existsP(nsPath):
      let raw = readText(nsPath).strip()
      try:
        if parseInt(raw) > 0: enabled = true
      except ValueError:
        discard
  if enabled:
    rep.addFinding("kernel.userns", "kernel", "Unprivileged user namespaces enabled",
                   "user namespaces are available to unprivileged processes (a common exploit prerequisite)",
                   sevLow)

proc register*(reg: Registry) =
  reg.add("kernel.copyfail", "kernel", "CopyFail CVE-2026-31431", checkCopyFail)
  reg.add("kernel.cve", "kernel", "Kernel CVE check", checkCves)
  reg.add("kernel.userns", "kernel", "User namespaces", checkUserns)
