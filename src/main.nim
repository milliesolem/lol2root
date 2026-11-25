## main.nim - command line entry point.
## Parses options, assembles the check registry, runs checks (and optionally
## exploits), then renders the console report and/or writes JSON.

import std/[os, strutils, terminal, sets]
import core
import catalog
import exploits

const helpText = """
{tool} v{version} - Linux privilege escalation discovery & exploitation

USAGE:
  {tool} [options]

OPTIONS:
  -h, --help            show this help
  -e, --exploit         run automated exploitation where supported
  -a, --all             run slower / deeper checks too
  -q, --quiet           print only critical and high findings
  -j, --json            write an organized JSON report
  -o, --json-path PATH  JSON output path (default: lol2root.json)
  -c, --only LIST       restrict to categories (comma separated)
  -f, --output PATH     also write the console report to PATH
  -t, --timeout SECS    per-command timeout (default: 4)
      --color           force ANSI colors
      --no-color        disable ANSI colors

CATEGORIES:
  system, files, services, network, kernel

EXAMPLES:
  {tool}                       run every check, pretty console output
  {tool} -j -o scan.json       run checks and write a JSON report
  {tool} -e                    run checks, then exploit safe primitives
  {tool} -c system,kernel      only run the system and kernel checks
""".multiReplace(("{tool}", toolName), ("{version}", version))

proc parseOptions(): Options =
  result = Options(timeoutSec: 4)
  result.only = initHashSet[string]()
  var colorExplicit = false

  let args = commandLineParams()
  var i = 0
  proc needValue(name: string): string =
    ## Returns the value bound to `name`, either inline (`--name=value` /
    ## `-nvalue`) or as the next argument. Exits with an error when absent.
    if i + 1 < args.len:
      inc i
      return args[i]
    stderr.writeLine("option " & name & " requires a value")
    quit(2)

  while i < args.len:
    let a = args[i]
    var name = a
    var inlineVal = ""
    if a.startsWith("--"):
      let eq = a.find('=')
      if eq > 0:
        name = a[0 ..< eq]
        inlineVal = a[eq + 1 .. ^1]
    elif a.startsWith("-") and a.len > 1:
      name = a[0 .. 1]
      if a.len > 2:
        inlineVal = a[2 .. ^1]
        if inlineVal.startsWith("="):
          inlineVal = inlineVal[1 .. ^1]

    proc valueOf(): string =
      if inlineVal.len > 0: inlineVal else: needValue(name)

    case name
    of "--help", "-h":
      echo helpText
      quit(0)
    of "--exploit", "-e":
      result.exploit = true
    of "--all", "-a":
      result.all = true
    of "--quiet", "-q":
      result.quiet = true
    of "--json", "-j":
      result.jsonLog = true
      if inlineVal.len > 0:
        result.jsonPath = inlineVal
    of "--json-path", "-o":
      result.jsonPath = valueOf()
      result.jsonLog = true
    of "--only", "-c":
      for cat in valueOf().split(','):
        let c = cat.strip().toLowerAscii()
        if c.len > 0: result.only.incl c
    of "--output", "-f":
      result.outputFile = valueOf()
    of "--timeout", "-t":
      result.timeoutSec = parseInt(valueOf())
    of "--color":
      result.color = true
      colorExplicit = true
    of "--no-color":
      result.color = false
      colorExplicit = true
    else:
      stderr.writeLine("unknown option: " & name)
      stderr.writeLine(helpText)
      quit(2)
    inc i

  if not colorExplicit:
    result.color = isatty(stdout)
    if existsEnv("NO_COLOR"): result.color = false

proc main() =
  let opts = parseOptions()
  let rep = newReporter()

  let reg = buildRegistry()
  var ran = 0
  for def in reg.defs:
    if opts.only.len > 0 and def.category notin opts.only:
      continue
    def.run(opts, rep)
    inc ran

  if ran == 0:
    stderr.writeLine("no checks matched the requested categories")
    quit(2)

  if opts.exploit:
    runExploits(opts, rep)

  let text = render(rep, opts)
  echo text

  if opts.outputFile.len > 0:
    try:
      writeFile(opts.outputFile, text & "\n")
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
