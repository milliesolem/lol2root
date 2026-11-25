import std/[unittest, strutils]
import checks/kernel

proc k(maj, min, pat: int): KVer = (maj: maj, min: min, pat: pat)

suite "kernel helpers":
  test "parseKernelVersion":
    var v = parseKernelVersion("6.12.48+deb13-amd64")
    check (v.maj, v.min, v.pat) == (6, 12, 48)
    v = parseKernelVersion("5.15.0-91-generic")
    check (v.maj, v.min, v.pat) == (5, 15, 0)
    v = parseKernelVersion("3.10.0-1160")
    check (v.maj, v.min, v.pat) == (3, 10, 0)
    v = parseKernelVersion("not a kernel")
    check (v.maj, v.min, v.pat) == (0, 0, 0)

  test "versionLt and versionGe":
    check versionLt(k(5, 8, 0), k(5, 16, 11))
    check not versionLt(k(6, 0, 0), k(5, 16, 11))
    check versionGe(k(6, 1, 170), k(6, 1, 169))

  test "isFixedUpstream":
    check isFixedUpstream(7, 0, 0)
    check isFixedUpstream(6, 19, 12)
    check not isFixedUpstream(6, 19, 11)
    check isFixedUpstream(6, 12, 85)
    check isFixedUpstream(6, 6, 137)
    check isFixedUpstream(6, 1, 170)
    check isFixedUpstream(5, 15, 204)
    check isFixedUpstream(5, 10, 254)
    check not isFixedUpstream(5, 10, 253)
    check not isFixedUpstream(4, 14, 0)

  test "findAeadConfigLine":
    let off = findAeadConfigLine("# CONFIG_CRYPTO_USER_API_AEAD is not set")
    check off.len > 0
    check "CONFIG_CRYPTO_USER_API_AEAD" in off
    let builtin = findAeadConfigLine("CONFIG_CRYPTO_USER_API_AEAD=y")
    check builtin.len > 0
    check "CONFIG_CRYPTO_USER_API_AEAD" in builtin
    check findAeadConfigLine("CONFIG_FOO=y\nCONFIG_BAR=m") == ""

  test "classifyAeadConfig":
    check classifyAeadConfig("CONFIG_CRYPTO_USER_API_AEAD is not set") == "off"
    check classifyAeadConfig("CONFIG_CRYPTO_USER_API_AEAD=y") == "builtin"
    check classifyAeadConfig("CONFIG_CRYPTO_USER_API_AEAD=m") == "module"

  test "parseGlibcVersion":
    let (gmaj, gmin) = parseGlibcVersion("ldd (Debian GLIBC 2.41-1) 2.41")
    check gmaj == 2
    check gmin == 41
