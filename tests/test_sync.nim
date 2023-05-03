import unittest
import sequtils

import nimldap/sync

const host = "ldap://ldap.forumsys.com:389"
const login = "cn=read-only-admin,dc=example,dc=com"
const pass = "password"

# template test(n, body) =
#   block:
#     body
# template check(body) =
#   doAssert body
# template expect(ex, body) =
#   try:
#     body
#     doAssert false
#   except LdapException:
#     discard

var ld: LdapRef

test "failedBind1":
  expect LdapException:
    let l = newLdap("ldap://error-389389.noway:389")
    l.saslBind(login, pass)

test "failedBind2":
  expect LdapException:
    let l = newLdap(host)
    l.saslBind("nouser", pass)

test "init":
  ld = newLdap(host)

test "bind":
  ld.saslBind(login, pass)

test "whoami":
  check "dn:cn=read-only-admin,dc=example,dc=com" == ld.whoAmI()

test "count":
  check 21 == ld.count("(objectclass=*)")

test "count_with_page":
  check 21 == ld.count("(objectclass=*)", pageSize = 10)

test "iterator":
  var eCount = 0
  var aCount = 0
  var aLenCount = 0
  var vCount = 0
  var vLenCount = 0
  for e in ld.search("(objectclass=*)"):
    inc eCount
    for a, vs in e:
      inc aCount
      aLenCount.inc a.len
      for v in vs:
        inc vCount
        vLenCount += len $v
  check 21 == eCount
  check 108 == aCount
  check 613 == aLenCount
  check 170 == vCount
  check 2069 == vLenCount

test "search":
  let res = toSeq(ld.search("(objectclass=*)"))
  check "dc=example,dc=com" == res[0].dn()
  check "cn=admin,dc=example,dc=com" == res[1].dn()
  check "uid=newton,dc=example,dc=com" == res[2].dn()
  check @["sn", "objectClass", "uid", "mail", "cn"] == res[
      2].attrs()
  check "newton@ldap.forumsys.com" == res[2]["mail"]
  check @["inetOrgPerson", "organizationalPerson", "person", "top"] == res[2]{"objectClass"}

test "search_with_page":
  let res = toSeq(ld.search("(objectclass=*)", pageSize = 10))
  check "dc=example,dc=com" == res[0].dn()
  check "cn=admin,dc=example,dc=com" == res[1].dn()
  check "uid=newton,dc=example,dc=com" == res[2].dn()
  check @["sn", "objectClass", "uid", "mail", "cn"] == res[
      2].attrs()
  check "newton@ldap.forumsys.com" == res[2]["mail"]
  check @["inetOrgPerson", "organizationalPerson", "person", "top"] == res[2]{"objectClass"}

test "controls_fail":
  expect LdapException:
    discard toSeq ld.search("(objectclass=*)", ctrls = @[newCtrl(
        "1.2.840.113556.1.4.801")])

test "unbind":
  ld.unbind()
