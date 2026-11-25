## main.nim - command line entry point.
## Parses options, assembles the check registry, runs checks (and optionally
## exploits), then renders the console report and/or writes JSON.

import std/[os, strutils, terminal, sets]
import core
import catalog
import exploits

type
  OptKind = enum okFlag, okValue, okOptionalValue
  OptId = enum
    optNone,
    optHelp, optExploit, optAll, optQuiet, optJson, optJsonPath,
    optOnly, optOutput, optTimeout, optColor, optNoColor
  OptSpec = object
    short: string      # single-char key, without the leading dash
    long: string       # long key, without the leading dashes
    kind: OptKind
    valueName: string  # placeholder shown in help for value-taking options
    help: string

const optSpecs: array[OptId, OptSpec] = [
  optNone: OptSpec(),
  optHelp: OptSpec(short: "h", long: "help", kind: okFlag,
                   help: "show this help"),
  optExploit: OptSpec(short: "e", long: "exploit", kind: okFlag,
                      help: "run automated exploitation where supported"),
  optAll: OptSpec(short: "a", long: "all", kind: okFlag,
                  help: "run slower / deeper checks too"),
  optQuiet: OptSpec(short: "q", long: "quiet", kind: okFlag,
                    help: "print only critical and high findings"),
  optJson: OptSpec(short: "j", long: "json", kind: okOptionalValue, valueName: "PATH",
                   help: "write an organized JSON report"),
  optJsonPath: OptSpec(short: "o", long: "json-path", kind: okValue, valueName: "PATH",
                       help: "JSON output path (default: lol2root.json)"),
  optOnly: OptSpec(short: "c", long: "only", kind: okValue, valueName: "LIST",
                   help: "restrict to categories (comma separated)"),
  optOutput: OptSpec(short: "f", long: "output", kind: okValue, valueName: "PATH",
                     help: "also write the console report to PATH"),
  optTimeout: OptSpec(short: "t", long: "timeout", kind: okValue, valueName: "SECS",
                      help: "per-command timeout (default: 4)"),
  optColor: OptSpec(long: "color", kind: okFlag, help: "force ANSI colors"),
  optNoColor: OptSpec(long: "no-color", kind: okFlag, help: "disable ANSI colors"),
]

proc renderHelp(): string =
  ## Help text generated from `optSpecs` (single source of truth for parsing
  ## and usage) plus the category list read from the check registry.
  var cats: seq[string] = @[]
  for def in buildRegistry().defs:
    if def.category notin cats:
      cats.add def.category

  var lines: seq[string] = @[
    toolName & " v" & version & " - Linux privilege escalation discovery & exploitation",
    "",
    "USAGE:",
    "  " & toolName & " [options]",
    "",
    "OPTIONS:",
  ]
  for spec in optSpecs:
    if spec.short.len == 0 and spec.long.len == 0:
      continue
    var flag = ""
    if spec.short.len > 0: flag.add "-" & spec.short
    if spec.long.len > 0:
      if flag.len > 0: flag.add ", "
      flag.add "--" & spec.long
    case spec.kind
    of okValue: flag.add " " & spec.valueName
    of okOptionalValue: flag.add " [" & spec.valueName & "]"
    of okFlag: discard
    lines.add "  " & flag.alignLeft(22) & spec.help

  lines.add ""
  lines.add "CATEGORIES:"
  lines.add "  " & cats.join(", ")
  lines.add ""
  lines.add "EXAMPLES:"
  for (args, desc) in [("", "run every check, pretty console output"),
                       ("-j -o scan.json", "run checks and write a JSON report"),
                       ("-e", "run checks, then exploit safe primitives"),
                       ("-c system,kernel", "only run the system and kernel checks")]:
    let cmd = if args.len > 0: toolName & " " & args else: toolName
    lines.add "  " & cmd.alignLeft(30) & desc
  result = lines.join("\n")

proc findOptId(isLong: bool, key: string): OptId =
  result = optNone
  for id, spec in optSpecs:
    if isLong:
      if spec.long.len > 0 and spec.long == key: return id
    elif spec.short.len > 0 and spec.short == key:
      return id

proc parseOptions(): Options =
  result = Options(timeoutSec: 4)
  result.only = initHashSet[string]()
  var colorExplicit = false

  let args = commandLineParams()
  var i = 0
  proc takeValue(flag, inline: string): string =
    if inline.len > 0: return inline
    if i + 1 < args.len:
      inc i
      return args[i]
    stderr.writeLine("option " & flag & " requires a value")
    quit(2)

  while i < args.len:
    let a = args[i]
    var isLong = false
    var key = ""
    var inlineVal = ""
    if a.startsWith("--"):
      isLong = true
      let eq = a.find('=')
      if eq > 0:
        key = a[2 ..< eq]
        inlineVal = a[eq + 1 .. ^1]
      else:
        key = a[2 .. ^1]
    elif a.startsWith("-") and a.len > 1:
      isLong = false
      key = a[1 .. 1]
      if a.len > 2:
        inlineVal = a[2 .. ^1]
        if inlineVal.startsWith("="): inlineVal = inlineVal[1 .. ^1]

    let id = findOptId(isLong, key)
    if id == optNone:
      stderr.writeLine("unknown option: " & a)
      stderr.writeLine(renderHelp())
      quit(2)

    case id
    of optHelp:
      echo renderHelp()
      quit(0)
    of optExploit: result.exploit = true
    of optAll: result.all = true
    of optQuiet: result.quiet = true
    of optJson:
      result.jsonLog = true
      if inlineVal.len > 0: result.jsonPath = inlineVal
    of optJsonPath:
      result.jsonPath = takeValue(a, inlineVal)
      result.jsonLog = true
    of optOnly:
      for cat in takeValue(a, inlineVal).split(','):
        let c = cat.strip().toLowerAscii()
        if c.len > 0: result.only.incl c
    of optOutput:
      result.outputFile = takeValue(a, inlineVal)
    of optTimeout:
      result.timeoutSec = parseInt(takeValue(a, inlineVal))
    of optColor:
      result.color = true
      colorExplicit = true
    of optNoColor:
      result.color = false
      colorExplicit = true
    of optNone: discard
    inc i

  if not colorExplicit:
    result.color = isatty(stdout)
    if existsEnv("NO_COLOR"): result.color = false

proc progressBar(pos, total: int): string =
  ## Compact `[####····]  42%  (9/21)` status bar. `pos` is the 1-based item
  ## currently in progress, so the first check shows 1/total and the last 100%.
  const width = 22
  let p = if total <= 0: 0 else: max(0, min(total, pos))
  let filled = if total <= 0: 0 else: min(width, (p * width) div total)
  let pct = if total <= 0: 0 else: (p * 100) div total
  "[" & "#".repeat(filled) & "·".repeat(width - filled) & "] " &
  align($pct, 3) & "%  (" & align($p, len($total)) & "/" & $total & ")"

proc eraseStatus() =
  stdout.write("\r" & " ".repeat(96) & "\r")
  stdout.flushFile()

proc main() =
  let opts = parseOptions()
  let rep = newReporter()

  let reg = buildRegistry()
  var selected: seq[CheckDef] = @[]
  for def in reg.defs:
    if opts.only.len > 0 and def.category notin opts.only:
      continue
    selected.add def
  if selected.len == 0:
    stderr.writeLine("no checks matched the requested categories")
    quit(2)

  # Banner + host line appear instantly, before any slow check runs.
  echo bannerText()
  echo ""
  echo renderHostLine(opts)
  echo ""

  let interactive = isatty(stdout)
  let total = selected.len + (if opts.exploit: 1 else: 0)
  var done = 0

  if not interactive:
    echo "running " & $total & " check" & (if total == 1: "" else: "s") & "…"

  for def in selected:
    if interactive:
      eraseStatus()
      stdout.write(progressBar(done + 1, total) & "  " & def.title)
      stdout.flushFile()
    try:
      def.run(opts, rep)
    except CatchableError as e:
      stderr.writeLine("check '" & def.id & "' failed: " & e.msg)
    inc done

  if opts.exploit:
    if interactive:
      eraseStatus()
      stdout.write(progressBar(total, total) & "  exploitation")
      stdout.flushFile()
    try:
      runExploits(opts, rep)
    except CatchableError as e:
      stderr.writeLine("exploitation failed: " & e.msg)
    inc done

  if interactive:
    eraseStatus()

  echo renderFindings(rep, opts)

  if opts.outputFile.len > 0:
    try:
      writeFile(opts.outputFile, render(rep, opts) & "\n")
      stderr.writeLine("console report written to " & opts.outputFile)
    except CatchableError as e:
      stderr.writeLine("could not write console report: " & e.msg)

  if opts.jsonLog:
    let path = if opts.jsonPath.len > 0: opts.jsonPath else: "lol2root.json"
    try:
      writeFile(path, jsonReport(rep) & "\n")
      stderr.writeLine("json report written to " & path)
    except CatchableError as e:
      stderr.writeLine("could not write json report: " & e.msg)

when isMainModule:
  main()
