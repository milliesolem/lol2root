import std/[unittest, json, strutils]
import core

suite "core helpers":
  test "severityTag":
    check severityTag(sevCritical) == "CRIT"
    check severityTag(sevHigh) == "HIGH"
    check severityTag(sevMed) == "MED "
    check severityTag(sevLow) == "LOW "
    check severityTag(sevInfo) == "INFO"

  test "paint":
    check paint("hello", "\e[31m", false) == "hello"
    check paint("hello", "\e[31m", true) == "\e[31mhello\e[0m"

  test "indentBlock":
    check indentBlock("a\nb\n\nc", 2) == "  a\n  b\n\n  c"

  test "findings sorting":
    var rep = newReporter()
    rep.addFinding("a", "cat", "Low title", "d", sevLow)
    rep.addFinding("b", "cat", "Critical title", "d", sevCritical)
    rep.addFinding("c", "cat", "High title", "d", sevHigh)
    rep.sortFindings()
    check rep.findings.len == 3
    check rep.findings[0].severity == sevCritical
    check rep.findings[1].severity == sevHigh
    check rep.findings[2].severity == sevLow

  test "render":
    var rep = newReporter()
    rep.addFinding("a", "system", "CRITICAL TITLE", "crit detail", sevCritical)
    rep.addFinding("b", "system", "INFO TITLE", "info detail", sevInfo)
    let rendered = render(rep, Options(color: false))
    check "CRITICAL TITLE" in rendered
    check "INFO TITLE" in rendered
    check "\e[" notin rendered
    check "SYSTEM" in rendered

  test "jsonReport":
    var rep = newReporter()
    rep.addFinding("a", "cat", "Critical", "d", sevCritical)
    rep.addFinding("b", "cat", "Low", "d", sevLow)
    let j = parseJson(jsonReport(rep))
    check j["tool"].kind == JString
    check j["findings"].kind == JArray
    check j["findings"].len == 2
    check j["summary"]["critical"].getInt == 1
