import unittest
import std/asyncdispatch

import nimldap

const host = "ldap://ldap.forumsys.com:389"
const login = "cn=read-only-admin,dc=example,dc=com"
const pass = "password"

# template test(n, body) =
#   block:
#     body
# template check(body) =
#   doAssert body

var ld: LdapAsyncRef

test "init":
  ld = newLdapAsync(host)

test "bind":
  waitFor ld.saslBind(login, pass)

test "whoami":
  check "dn:cn=read-only-admin,dc=example,dc=com" == waitFor ld.whoAmI()

test "count":
  check 21 == waitFor ld.count("(objectclass=*)")

test "count_with_page":
  check 21 == waitFor ld.count("(objectclass=*)", pageSize = 10)

test "search":
  var res = newSeq[EntryAsync]()
  let s = ld.search("(objectclass=*)")
  while true:
    let e = waitFor s.next()
    if e.done:
      break
    res.add e
  check 21 == res.len
  check "dc=example,dc=com" == res[0].dn()
  check "cn=admin,dc=example,dc=com" == res[1].dn()
  check "uid=newton,dc=example,dc=com" == res[2].dn()
  check @["sn", "objectClass", "uid", "mail", "cn"] == res[
      2].attrs()
  check "newton@ldap.forumsys.com" == res[2]["mail"]
  check @["inetOrgPerson", "organizationalPerson", "person", "top"] == res[2]{"objectClass"}

test "search_with_page":
  var res = newSeq[EntryAsync]()
  let s = ld.search("(objectclass=*)", pageSize = 10)
  while true:
    let e = waitFor s.next()
    if e.done:
      break
    res.add e
  check 21 == res.len
  check "dc=example,dc=com" == res[0].dn()
  check "cn=admin,dc=example,dc=com" == res[1].dn()
  check "uid=newton,dc=example,dc=com" == res[2].dn()
  check @["sn", "objectClass", "uid", "mail", "cn"] == res[
      2].attrs()
  check "newton@ldap.forumsys.com" == res[2]["mail"]
  check @["inetOrgPerson", "organizationalPerson", "person", "top"] == res[2]{"objectClass"}

test "iterator":
  var count = 0
  let s = ld.search "(objectclass=*)"
  while true:
    let entry = waitFor s.next()
    if entry.done:
      break
    for attr, vals in entry:
      inc count
  check 108 == count

test "iterator_ref":
  var count = 0

  proc f() {.async.} =
    let s = ld.search "(objectclass=*)"
    while true:
      let entry = await s.next()
      if entry.done:
        break
      for attr, vals in entry:
        for v in vals:
          inc count

  waitFor f()
  check 170 == count

# test "controls_fail": TEST FAILED
#   expect LdapException:
#     let s = ld.search("(objectclass=*)", ctrls = @[newCtrl("1.2.840.113556.1.4.801")])
#     discard waitFor s.next()
