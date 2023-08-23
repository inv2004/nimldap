import asyncdispatch
import strutils
import xmlparser
import xmltree
import sequtils

import nimldap

# The server does not support LDAP_SERVER_NOTIFICATION_OID
const host = "ldap://ldap.forumsys.com:389"
const login = "read-only-admin@example.com"
const pass = "password"

let ctrls = @[newCtrl Extension.LDAP_SERVER_NOTIFICATION_OID]

proc findChange(metas: seq[string]) =
  let idx = metas
    .mapIt(parseXml(it))
    .mapIt(it.findAll("usnLocalChange")[0].innerText.parseInt())
    .maxIndex()

  echo metas[idx]

proc main() {.async.} =
  let ld = newLdapAsync host
  await ld.saslBind(login, pass)
  echo waitFor ld.whoAmI()
  let s = ld.search("(objectclass=*)", attrs = @["+", "*",
      "msDS-ReplAttributeMetaData"], ctrls = ctrls)
  while true:
    let entry = await s.next()
    if entry.done:
      break
    echo entry.dn()
    findChange entry{"msDS-ReplAttributeMetaData"}

waitFor main()

