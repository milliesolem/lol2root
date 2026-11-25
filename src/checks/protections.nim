## checks/protections.nim - kernel / OS hardening checks.
##
## Contract: see checks/system.nim for the module conventions.
## Category: "protections". Only emit a finding when a protection is weak;
## a hardened setting is benign and stays silent.

import std/strutils
import ../core

# ---------------------------------------------------------------------------
# Small helpers local to this module
# ---------------------------------------------------------------------------

proc sysctl(path: string): string =
  readText(path).strip()

proc sysctlInt(path: string): int =
  try:
    parseInt(sysctl(path))
  except ValueError:
    -1

# ---------------------------------------------------------------------------
# 1. protections.aslr - address space layout randomization
# ---------------------------------------------------------------------------

proc checkAslr(opts: Options, rep: Reporter) =
  let v = sysctlInt("/proc/sys/kernel/randomize_va_space")
  case v
  of 0:
    rep.addFinding("protections.aslr", "protections", "ASLR disabled",
                   "randomize_va_space=0 fully disables address space layout " &
                   "randomization.", sevHigh)
  of 1:
    rep.addFinding("protections.aslr", "protections", "ASLR partial",
                   "randomize_va_space=1 randomizes only the stack and mmap " &
                   "base; the main executable and libraries stay predictable.",
                   sevLow)
  else:
    discard # 2 (full) or unknown: benign

# ---------------------------------------------------------------------------
# 2. protections.kptr_restrict - kernel pointer restriction
# ---------------------------------------------------------------------------

proc checkKptrRestrict(opts: Options, rep: Reporter) =
  if sysctlInt("/proc/sys/kernel/kptr_restrict") == 0:
    rep.addFinding("protections.kptr_restrict", "protections",
                   "Kernel pointers exposed",
                   "kptr_restrict=0: unprivileged users can read kernel " &
                   "addresses from /proc and dmesg, aiding a KASLR bypass.",
                   sevMed)

# ---------------------------------------------------------------------------
# 3. protections.dmesg_restrict - dmesg restriction
# ---------------------------------------------------------------------------

proc checkDmesgRestrict(opts: Options, rep: Reporter) =
  if sysctlInt("/proc/sys/kernel/dmesg_restrict") == 0:
    rep.addFinding("protections.dmesg_restrict", "protections",
                   "dmesg readable by unprivileged users",
                   "dmesg_restrict=0: kernel messages (including leaked " &
                   "addresses) are readable without privileges.", sevLow)

# ---------------------------------------------------------------------------
# 4. protections.kallsyms - kernel symbol exposure
# ---------------------------------------------------------------------------

proc checkKallsyms(opts: Options, rep: Reporter) =
  if not readableByMe("/proc/kallsyms"):
    return
  let content = readText("/proc/kallsyms")
  if content.len == 0:
    return
  var nonEmpty = 0
  for line in content.splitLines():
    let l = line.strip()
    if l.len == 0:
      continue
    inc nonEmpty
    if nonEmpty > 20:
      break
    let fields = l.splitWhitespace()
    if fields.len == 0:
      continue
    # A real kernel address contains a non-zero hex digit; when kptr_restrict
    # hides them the first field is all '0' digits. Do not parse as an int:
    # real addresses exceed int64 and would wrap negative.
    var nonZero = false
    for c in fields[0]:
      if c in {'1'..'9', 'a'..'f', 'A'..'F'}:
        nonZero = true
        break
    if nonZero:
      rep.addFinding("protections.kallsyms", "protections",
                     "Kernel symbols readable with real addresses",
                     "Kernel symbol table exposes real kernel addresses, " &
                     "leaking the KASLR base.", sevLow)
      return

# ---------------------------------------------------------------------------
# 5. protections.yama - Yama ptrace_scope
# ---------------------------------------------------------------------------

proc checkYama(opts: Options, rep: Reporter) =
  if sysctlInt("/proc/sys/kernel/yama/ptrace_scope") == 0:
    rep.addFinding("protections.yama", "protections",
                   "Yama ptrace_scope disabled",
                   "ptrace_scope=0 allows any process to ptrace any other " &
                   "process it can signal.", sevLow)

# ---------------------------------------------------------------------------
# 6. protections.unprivileged_bpf - unprivileged BPF
# ---------------------------------------------------------------------------

proc checkUnprivilegedBpf(opts: Options, rep: Reporter) =
  if sysctlInt("/proc/sys/kernel/unprivileged_bpf_disabled") == 0:
    rep.addFinding("protections.unprivileged_bpf", "protections",
                   "Unprivileged BPF enabled",
                   "unprivileged_bpf_disabled=0: unprivileged users can load " &
                   "BPF programs, a large kernel attack surface.", sevLow)

# ---------------------------------------------------------------------------
# 7. protections.mmap_min_addr - NULL mmap restriction
# ---------------------------------------------------------------------------

proc checkMmapMinAddr(opts: Options, rep: Reporter) =
  if sysctlInt("/proc/sys/vm/mmap_min_addr") == 0:
    rep.addFinding("protections.mmap_min_addr", "protections",
                   "NULL mmap allowed (mmap_min_addr=0)",
                   "vm.mmap_min_addr=0 permits mapping memory at address 0, " &
                   "enabling NULL-pointer dereference exploitation.", sevMed)

# ---------------------------------------------------------------------------
# 8. protections.protected_hardlinks - hardlink protection
# ---------------------------------------------------------------------------

proc checkProtectedHardlinks(opts: Options, rep: Reporter) =
  if sysctlInt("/proc/sys/fs/protected_hardlinks") == 0:
    rep.addFinding("protections.protected_hardlinks", "protections",
                   "Hardlink protection disabled",
                   "fs.protected_hardlinks=0 lets unprivileged users hardlink " &
                   "files they do not own.", sevMed)

# ---------------------------------------------------------------------------
# 9. protections.protected_symlinks - symlink protection
# ---------------------------------------------------------------------------

proc checkProtectedSymlinks(opts: Options, rep: Reporter) =
  if sysctlInt("/proc/sys/fs/protected_symlinks") == 0:
    rep.addFinding("protections.protected_symlinks", "protections",
                   "Symlink protection disabled",
                   "fs.protected_symlinks=0 lets unprivileged users follow " &
                   "symlinks in world-writable directories they do not own.",
                   sevMed)

# ---------------------------------------------------------------------------
# 10. protections.suid_dumpable - SUID core dumps
# ---------------------------------------------------------------------------

proc checkSuidDumpable(opts: Options, rep: Reporter) =
  let v = sysctlInt("/proc/sys/fs/suid_dumpable")
  if v == 1 or v == 2:
    rep.addFinding("protections.suid_dumpable", "protections",
                   "SUID core dumps allowed",
                   "fs.suid_dumpable=" & $v & ": core dumps from privileged " &
                   "processes may be written, potentially leaking secrets.",
                   sevLow)

# ---------------------------------------------------------------------------
# 11. protections.core_pattern - core dump handler
# ---------------------------------------------------------------------------

proc checkCorePattern(opts: Options, rep: Reporter) =
  let p = "/proc/sys/kernel/core_pattern"
  if writableByMe(p):
    rep.addFinding("protections.core_pattern", "protections",
                   "core_pattern writable",
                   "You can write an arbitrary command into core_pattern; it " &
                   "runs as root when a privileged process crashes.", sevHigh)
    return
  let v = readText(p).strip()
  if v.startsWith("|"):
    rep.addFinding("protections.core_pattern", "protections",
                   "Core dumps piped to a command",
                   "core_pattern=" & v, sevMed)

# ---------------------------------------------------------------------------
# 12. protections.lsm - LSM (AppArmor/SELinux) state
# ---------------------------------------------------------------------------

proc checkLsm(opts: Options, rep: Reporter) =
  var selinuxEnforcing = false
  var apparmorEnforced = false

  if which("getenforce"):
    let mode = run("getenforce 2>/dev/null").output.strip().toLowerAscii()
    if mode == "enforcing":
      selinuxEnforcing = true

  let profiles = "/sys/kernel/security/apparmor/profiles"
  if existsP(profiles):
    let text = readText(profiles)
    if text.len > 0 and text.contains("enforce"):
      apparmorEnforced = true

  if not (selinuxEnforcing or apparmorEnforced):
    rep.addFinding("protections.lsm", "protections",
                   "No enforcing LSM detected",
                   "Neither SELinux (enforcing) nor AppArmor (enforced) is " &
                   "active on this system.", sevLow)

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

proc register*(reg: Registry) =
  reg.add("protections.aslr", "protections", "ASLR", checkAslr)
  reg.add("protections.kptr_restrict", "protections",
          "Kernel pointer restriction", checkKptrRestrict)
  reg.add("protections.dmesg_restrict", "protections",
          "dmesg restriction", checkDmesgRestrict)
  reg.add("protections.kallsyms", "protections",
          "Kernel symbol exposure", checkKallsyms)
  reg.add("protections.yama", "protections", "Yama ptrace_scope", checkYama)
  reg.add("protections.unprivileged_bpf", "protections",
          "Unprivileged BPF", checkUnprivilegedBpf)
  reg.add("protections.mmap_min_addr", "protections",
          "mmap_min_addr", checkMmapMinAddr)
  reg.add("protections.protected_hardlinks", "protections",
          "Hardlink protection", checkProtectedHardlinks)
  reg.add("protections.protected_symlinks", "protections",
          "Symlink protection", checkProtectedSymlinks)
  reg.add("protections.suid_dumpable", "protections",
          "SUID core dumps", checkSuidDumpable)
  reg.add("protections.core_pattern", "protections",
          "Core dump handler", checkCorePattern)
  reg.add("protections.lsm", "protections", "LSM (AppArmor/SELinux)", checkLsm)
