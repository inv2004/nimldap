import nimldap
import strutils
import strformat

const host = "ldap://ldap.forumsys.com:389"
const login = "cn=read-only-admin,dc=example,dc=com"
const pass = "password"

let ld = newLdap host
ld.saslBind login, pass
echo ld.whoAmI()

for entry in ld.search("(objectclass=*)", @[""], LdapScope.Base, ""):
  echo entry.getDN()
  for attr, vals in entry:
    echo fmt"""  {attr} ({vals.len}): {(vals.values().join", ")}"""

# for entry in ld.search("(objectclass=*)", ctrls = @[newCtrl Extension.LDAP_SERVER_NOTIFICATION_OID]):
for entry in ld.search "(objectclass=*)":
  echo entry.getDN()
  for attr, vals in entry:
    echo fmt"""  {attr} ({vals.len}): {(vals.values().join", ")}"""
