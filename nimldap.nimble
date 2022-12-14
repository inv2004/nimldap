# Package

version       = "0.5.1"
author        = "inv2004"
description   = "LDAP client bindings"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 1.6.8"
requires "stew"

task fulltest, "valgrind memleak":
  for f in listFiles("tests"):
    if f.endsWith ".nim":
      exec "nim c --forceBuild --gc:orc -d:useMalloc " & f
      exec "valgrind --error-exitcode=1 --leak-check=yes --errors-for-leak-kinds=definite " & f[0..^5]
