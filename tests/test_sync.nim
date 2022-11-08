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
  check 23 == ld.count("(objectclass=*)")

test "count_with_page":
  check 23 == ld.count("(objectclass=*)", pageSize = 10)

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
  check 23 == eCount
  check 120 == aCount
  check 687 == aLenCount
  check 190 == vCount
  check 2333 == vLenCount

test "search":
  let res = toSeq(ld.search("(objectclass=*)"))
  check "dc=example,dc=com" == res[0].getDN()
  check "cn=admin,dc=example,dc=com" == res[1].getDN()
  check "uid=jmacy,dc=example,dc=com" == res[22].getDN()
  check @["uid", "telephoneNumber", "sn", "cn", "objectClass", "mail"] == res[
      22].attrs()
  check "jmacy-training@forumsys.com" == res[22]["mail"]
  check @["inetOrgPerson", "organizationalPerson", "person", "top"] == res[22]{"objectClass"}

test "search_with_page":
  let res = toSeq(ld.search("(objectclass=*)", pageSize=10))
  check "dc=example,dc=com" == res[0].getDN()
  check "cn=admin,dc=example,dc=com" == res[1].getDN()
  check "uid=jmacy,dc=example,dc=com" == res[22].getDN()
  check @["uid", "telephoneNumber", "sn", "cn", "objectClass", "mail"] == res[
      22].attrs()
  check "jmacy-training@forumsys.com" == res[22]["mail"]
  check @["inetOrgPerson", "organizationalPerson", "person", "top"] == res[22]{"objectClass"}

test "controls_fail":
  expect LdapException:
    discard toSeq ld.search("(objectclass=*)", ctrls = @[newCtrl(
        "1.2.840.113556.1.4.801")])

test "unbind":
  ld.unbind()
