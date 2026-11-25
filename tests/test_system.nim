import std/unittest
import core
import checks/system

suite "system helpers":
  test "containsKeyword":
    check containsKeyword("MY_KEY", "KEY")
    check not containsKeyword("KEYPRESS", "KEY")
    check not containsKeyword("MONKEY", "KEY")
    check containsKeyword("AWS_SECRET_ACCESS_KEY", "SECRET")

  test "isLoginShell":
    check isLoginShell("/bin/bash")
    check isLoginShell("/usr/bin/zsh")
    check not isLoginShell("/bin/bash.exe")
    check not isLoginShell("/usr/sbin/nologin")

  test "stripQuotes":
    check stripQuotes("\"Debian GNU/Linux 13 (trixie)\"") == "Debian GNU/Linux 13 (trixie)"
    check stripQuotes("no quotes") == "no quotes"

  test "groupSeverity":
    check groupSeverity("docker") == sevHigh
    check groupSeverity("lxd") == sevHigh
    check groupSeverity("wheel") == sevMed
    check groupSeverity("sudo") == sevMed
    check groupSeverity("shadow") == sevLow
    check groupSeverity("disk") == sevLow
    check groupSeverity("games") == sevInfo

  test "capSeverity":
    check capSeverity("cap_setuid+ep") == sevHigh
    check capSeverity("cap_net_admin+ep") == sevMed
    check capSeverity("cap_chown+ep") == sevInfo
