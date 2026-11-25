## checks/container.nim - container / virtualization detection.
##
## Contract: see checks/system.nim for the module conventions.
## Category: "container".
##
## Only emits a finding when a container or virtualization marker is actually
## detected; a bare metal host with no markers stays silent.

import std/strutils
import ../core

const cat = "container"

# ---------------------------------------------------------------------------
# 1. container.dockerenv - Docker marker file
# ---------------------------------------------------------------------------

proc checkDockerEnv(opts: Options, rep: Reporter) =
  if existsP("/.dockerenv"):
    rep.addFinding("container.dockerenv", cat, "Docker container marker",
      "/.dockerenv exists; this process is likely inside a Docker container.",
      sevInfo)

# ---------------------------------------------------------------------------
# 2. container.cgroup - container runtime from /proc/1/cgroup
# ---------------------------------------------------------------------------

proc checkCgroup(opts: Options, rep: Reporter) =
  let text = readText("/proc/1/cgroup")
  if text.len == 0:
    return

  let lower = text.toLowerAscii()
  let markers = [("kubepods", "Kubernetes"), ("docker", "docker"),
                 ("containerd", "containerd"), ("libpod", "Podman"), ("lxc", "lxc")]
  for (marker, _) in markers:
    if lower.contains(marker):
      var detail = "cgroup does not clearly identify the runtime."
      for line in text.splitLines():
        if line.toLowerAscii().contains(marker):
          detail = line.strip()
          break
      rep.addFinding("container.cgroup", cat, "Container runtime: " & marker,
        detail, sevInfo)
      return

# ---------------------------------------------------------------------------
# 3. container.mountinfo - container filesystem markers
# ---------------------------------------------------------------------------

proc checkMountinfo(opts: Options, rep: Reporter) =
  var text = readText("/proc/self/mountinfo")
  if text.len == 0:
    text = readText("/proc/1/mountinfo")
  if text.len == 0:
    return

  let lower = text.toLowerAscii()
  var found: seq[string] = @[]
  for marker in ["overlay", "docker", "containerd"]:
    if lower.contains(marker):
      found.add marker
  if found.len > 0:
    rep.addFinding("container.mountinfo", cat, "Container filesystem detected",
      "mountinfo markers: " & found.join(", "), sevInfo)

# ---------------------------------------------------------------------------
# 4. container.privileged - dangerous capabilities on this process
# ---------------------------------------------------------------------------

proc checkPrivileged(opts: Options, rep: Reporter) =
  let status = readText("/proc/self/status")
  if status.len == 0:
    return

  var capEff: uint64 = 0
  var parsed = false
  for line in status.splitLines():
    if line.startsWith("CapEff:"):
      let value = line["CapEff:".len .. ^1].strip()
      if value.len > 0:
        try:
          capEff = fromHex[uint64](value)
          parsed = true
        except ValueError:
          discard
      break
  if not parsed:
    return

  const caps = [("cap_sys_admin", 21), ("cap_dac_read_search", 2),
                ("cap_sys_module", 16)]
  var present: seq[string] = @[]
  for (name, bit) in caps:
    if (capEff and (1'u64 shl bit)) != 0:
      present.add name

  if present.len > 0:
    rep.addFinding("container.privileged", cat, "Privileged container",
      "process holds dangerous capabilities: " & present.join(", "), sevHigh)

# ---------------------------------------------------------------------------
# 5. container.k8s - readable Kubernetes service account token
# ---------------------------------------------------------------------------

proc checkK8s(opts: Options, rep: Reporter) =
  for base in ["/var/run/secrets/kubernetes.io/serviceaccount",
               "/run/secrets/kubernetes.io/serviceaccount"]:
    if existsP(base) and readableByMe(base & "/token"):
      rep.addFinding("container.k8s", cat, "Kubernetes service account token",
        "readable service account token at " & base & "/token", sevHigh,
        @["https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/attacking-kubernetes-from-inside-a-pod"])
      return

# ---------------------------------------------------------------------------
# 6. container.seccomp - seccomp not applied
# ---------------------------------------------------------------------------

proc checkSeccomp(opts: Options, rep: Reporter) =
  let status = readText("/proc/self/status")
  if status.len == 0:
    return

  for line in status.splitLines():
    if line.startsWith("Seccomp:"):
      let value = line["Seccomp:".len .. ^1].strip()
      if value == "0":
        rep.addFinding("container.seccomp", cat, "No seccomp filtering",
          "/proc/self/status Seccomp: 0 — no seccomp profile is applied.",
          sevLow)
      break

# ---------------------------------------------------------------------------
# 7. container.virt - virtualization detection
# ---------------------------------------------------------------------------

proc checkVirt(opts: Options, rep: Reporter) =
  if which("systemd-detect-virt"):
    let r = run("systemd-detect-virt 2>/dev/null", opts.timeoutSec)
    let t = r.output.strip()
    if t.len > 0 and t != "none" and t != "bare metal":
      rep.addFinding("container.virt", cat, "Virtualization", t, sevInfo)
  else:
    let osrelease = readText("/proc/sys/kernel/osrelease")
    if osrelease.toLowerAscii().contains("microsoft"):
      rep.addFinding("container.virt", cat, "Virtualization",
        "WSL (Windows Subsystem for Linux)", sevInfo)

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

proc register*(reg: Registry) =
  reg.add("container.dockerenv", cat, "Docker container marker", checkDockerEnv)
  reg.add("container.cgroup", cat, "Container runtime", checkCgroup)
  reg.add("container.mountinfo", cat, "Container filesystem", checkMountinfo)
  reg.add("container.privileged", cat, "Privileged container", checkPrivileged)
  reg.add("container.k8s", cat, "Kubernetes service account token", checkK8s)
  reg.add("container.seccomp", cat, "Seccomp status", checkSeccomp)
  reg.add("container.virt", cat, "Virtualization", checkVirt)
