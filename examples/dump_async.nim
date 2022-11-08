import asyncdispatch
import strutils
import strformat

import nimldap

const host = "ldap://ldap.forumsys.com:389"
const login = "cn=read-only-admin,dc=example,dc=com"
const pass = "password"

proc main() {.async.} =
  let ld = newLdapAsync host
  await ld.saslBind(login, pass)
  echo waitFor ld.whoAmI()
  let s = ld.search "(objectclass=*)"
  while true:
    let entry = await s.next()
    if entry.done:
      break
    echo entry.getDN()
    for attr in entry:
      let vals = entry{attr}
      echo fmt"""  {attr} ({vals.len}): {(vals.join", ")}"""

waitFor main()
