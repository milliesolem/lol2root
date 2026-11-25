## checks/network.nim - interfaces, ports, sockets and container/cloud leads.
##
## Contract: see checks/system.nim for the module conventions.

import std/strutils
import ../core

const cat = "network"

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

proc writable(p: string): bool =
  ## True when `p` exists and the current user can write it. `test -w`
  ## also covers non-regular files such as sockets.
  run("test -w " & p & " 2>/dev/null").exitCode == 0

proc inDockerGroup(): bool =
  for cmd in ["id -Gn 2>/dev/null", "groups 2>/dev/null"]:
    let r = run(cmd, 3)
    for g in r.output.splitWhitespace():
      if g == "docker":
        return true
  false

proc splitLocal(s: string): tuple[address, port: string] =
  ## Split a `Local Address:Port` column (ss or netstat format) into its
  ## address and port parts. Handles IPv6 `[::]:port` and wildcard `:::port`.
  if s.len > 0 and s[0] == '[':
    let close = s.find(']')
    if close >= 0:
      let address = s[1 ..< close]
      var port = ""
      if close + 1 < s.len:
        port = s[close + 1 .. ^1].strip(leading = true, chars = {':'})
      return (address: address, port: port)
  let idx = s.rfind(':')
  if idx > 0:
    return (address: s[0 ..< idx], port: s[idx + 1 .. ^1])
  (address: s, port: "")

proc isLoopback(address: string): bool =
  let a = address.strip()
  a.len == 0 or a.startsWith("127.") or a == "::1"

proc ssProc(line: string): string =
  ## Extract the process name from an `ss` line: users:(("name",pid=...
  let marker = "users:("
  let i = line.find(marker)
  if i < 0:
    return ""
  var j = i + marker.len
  while j < line.len and line[j] == '(':
    inc j
  if j < line.len and line[j] == '"':
    inc j
    var name = ""
    while j < line.len and line[j] != '"':
      name.add line[j]
      inc j
    return name
  ""

proc netstatProc(parts: seq[string]): string =
  ## Extract the process name from a netstat line's PID/Program column.
  if parts.len < 7:
    return ""
  let p = parts[6]
  if p == "-" or p.len == 0:
    return ""
  let idx = p.find('/')
  if idx > 0 and idx + 1 < p.len:
    return p[idx + 1 .. ^1]
  p

# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

proc checkDocker(opts: Options, rep: Reporter) =
  var socketWritable = false
  for s in ["/var/run/docker.sock", "/run/docker.sock"]:
    if writable(s):
      socketWritable = true
      break

  if socketWritable:
    rep.addFinding("network.docker", cat, "Writable Docker socket",
      "The Docker daemon socket is writable by the current user. Talk to it or " &
      "mount the host filesystem from a container to escape (docker run -v /:/host ...).",
      sevCritical,
      @["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security"])
  elif inDockerGroup():
    rep.addFinding("network.docker", cat, "User in docker group",
      "The current user is in the `docker` group. Any docker command can mount " &
      "the host filesystem and escape the container.",
      sevHigh,
      @["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security"])

  if existsP("/.dockerenv"):
    rep.addFinding("network.docker.container", cat, "Running inside a container",
      "The /.dockerenv marker file is present, so this process is likely inside a container.",
      sevInfo)

proc checkPorts(opts: Options, rep: Reporter) =
  var txt = ""
  if which("ss"):
    txt = run("ss -tlnp 2>/dev/null", opts.timeoutSec).output
  if txt.strip().len == 0 and which("netstat"):
    txt = run("netstat -tlnp 2>/dev/null", opts.timeoutSec).output
  if txt.strip().len == 0:
    return

  var notable: seq[string] = @[]
  var loopbacks: seq[string] = @[]
  let isSs = txt.contains("users:")

  for raw in txt.splitLines():
    let l = raw.strip()
    if l.len == 0:
      continue
    if l.startsWith("State") or l.startsWith("Netid") or l.startsWith("Proto"):
      continue

    var local = ""
    var procName = ""
    if isSs:
      let parts = l.splitWhitespace()
      if parts.len < 4:
        continue
      if parts[0] != "LISTEN" and parts[0] != "UNCONN":
        continue
      local = parts[3]
      procName = ssProc(l)
    else:
      let parts = l.splitWhitespace()
      if parts.len < 7:
        continue
      if parts[5] != "LISTEN":
        continue
      local = parts[3]
      procName = netstatProc(parts)

    let la = splitLocal(local)
    let entry = if procName.len > 0: local & " (" & procName & ")" else: local
    if isLoopback(la.address):
      loopbacks.add entry
    else:
      notable.add entry

  var shown: seq[string]
  var note = ""
  if notable.len > 0:
    shown = notable
  elif loopbacks.len > 0:
    shown = loopbacks
    note = "loopback only"
  else:
    return

  let total = shown.len
  if shown.len > 25:
    shown = shown[0 ..< 25]
    shown.add "… (" & $total & " listeners, truncated)"

  var detail = ""
  if note.len > 0:
    detail.add note & "\n"
  detail.add shown.join("\n")
  if detail.len == 0:
    return

  rep.addFinding("network.ports", cat, "Listening ports", detail, sevInfo)

proc checkHosts(opts: Options, rep: Reporter) =
  let targets = [
    ("/etc/hosts", "network.hosts.hosts", "Writable /etc/hosts"),
    ("/etc/hostname", "network.hosts.hostname", "Writable /etc/hostname"),
    ("/etc/resolv.conf", "network.hosts.resolvconf", "Writable /etc/resolv.conf"),
    ("/etc/nsswitch.conf", "network.hosts.nsswitch", "Writable /etc/nsswitch.conf"),
  ]
  for (path, id, title) in targets:
    if writable(path):
      rep.addFinding(id, cat, title,
        path & " is writable by the current user; it can be modified to spoof " &
        "hostnames or hijack name resolution.",
        sevMed)

proc checkCloud(opts: Options, rep: Reporter) =
  var found: seq[string] = @[]

  let r = run("env 2>/dev/null", 3)
  for line in r.output.splitLines():
    let eq = line.find('=')
    if eq <= 0:
      continue
    let key = line[0 ..< eq]
    if key.startsWith("AWS_") or key.startsWith("GCP_") or
       key.startsWith("GOOGLE_") or key.startsWith("AZURE_") or
       key.startsWith("GCE_") or key.startsWith("EC2"):
      found.add "env: " & key

  let product = readText("/sys/class/dmi/id/product_name").strip().toLowerAscii()
  if product.len > 0:
    for marker in ["vmware", "amazon", "ec2", "qemu", "kvm", "virtualbox"]:
      if marker in product:
        found.add "dmi: " & product
        break

  let hv = readText("/sys/hypervisor/type").strip().toLowerAscii()
  if hv.len > 0 and hv != "bare metal":
    found.add "hypervisor: " & hv

  if found.len > 0:
    rep.addFinding("network.cloud", cat, "Cloud/virtual environment",
      "Passive indicators of a cloud or virtual machine environment:\n" &
      found.join("\n"),
      sevLow)

# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------

proc register*(reg: Registry) =
  reg.add("network.docker", cat, "Docker socket & container", checkDocker)
  reg.add("network.ports", cat, "Listening ports", checkPorts)
  reg.add("network.hosts", cat, "Writable network config", checkHosts)
  reg.add("network.cloud", cat, "Cloud/virtual environment", checkCloud)
