# Package

version       = "0.1.0"
author        = "solem.dev"
description   = "privilege escalation is a solved problem"
license       = "GPL-3.0"
srcDir        = "src"

# Dependencies

# Runs on the Nim standard library only: no external packages required.

task test, "Run the test suite":
  exec "nim c -r --hints:off --warnings:off --path:src --nimcache:/tmp/lol2root_testnc -o:/tmp/lol2root_tests tests/all.nim"
