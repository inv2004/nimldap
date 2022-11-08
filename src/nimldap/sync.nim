import bindings
import shared
import tinyasn1

export LdapRef, EntryAsync, getDN, attrs, `$`, `[]`, `{}`, len,
    LdapException, unbind, items, pairs, attrs, values,
    LdapScope, newCtrl, newPagingCtrl, Extension

proc newLdap*(url: string): LdapRef =
  new(result)
  checkErr ldap_initialize(result.r, url.cstring)
  result.setOption(LDAP_OPT_PROTOCOL_VERSION, LdapVersion.V3)
  result.setOption(LDAP_OPT_NETWORK_TIMEOUT, defaultNetworkTimeout)

proc saslBind*(ld: LdapRef, login, pass: string, dc = rootDC) =
  let creds = newBer(pass)
  checkErr ldap_sasl_bind_s(ld.r, login.cstring, LDAP_SASL_SIMPLE, creds,
      nil, nil, nil)
  ld.base = if dc == rootDC: extractDC login else: dc

proc whoAmI*(ld: LdapRef): string =
  var auth: Ber
  checkErr ldap_whoami_s(ld.r, auth.r, nil, nil)
  $auth.r[]

# ldapControl := ldap.NewControlString("1.2.840.113556.1.4.801", true, fmt.Sprintf("%c%c%c%c%c", 48, 3, 2, 1, 7))

proc searchMsg*(ld: LdapRef, filter: string, attrs: openArray[string] = ["*"],
    scope = LdapScope.SubTree, base = rootDC, limit = 0, ctrls: openArray[Ctrl] = [], pageSize = 0, pageCookie = ""): LdapMessageRef =
  let base = if base == rootDC: ld.base else: base
  let attrsC = allocCStringArray(attrs)
  defer: deallocCStringArray(attrsC)
  let ctrls = newCtrlsWithPage(ctrls, pageSize, pageCookie)
  let msg = LDAPMessageRef()

  checkErr ldap_search_ext_s(ld.r, base.cstring, scope.int,
      filter, attrsC, 0, ctrls.r, nil, nil, limit, msg)

  return msg

proc count*(ld: LdapRef, filter: string, scope = LdapScope.SubTree,
    base = rootDC, limit = 0, pageSize = 0): int =
  var cookie = ""
  while true:
    let msg = ld.searchMsg(filter, ["cn"], scope, base, limit, [], pageSize, cookie)
    result += ldap_count_entries(ld.r, msg.r)
    cookie = cookieFromMsg(ld, pageSize, msg)
    if cookie == "":
      break

iterator search*(ld: LdapRef, filter: string, attrs: openArray[string] = ["*"],
    scope = LdapScope.SubTree, base = rootDC, limit = 0, ctrls: openArray[Ctrl] = [], pageSize = 0): Entry =

  var cookie = ""
  while true:
    let msg = ld.searchMsg(filter, attrs, scope, base, limit, ctrls, pageSize, cookie)

    var entry = ldap_first_entry(ld.r, msg.r)
    while entry != nil:
      let e = Entry(entry: entry, msg: msg, ld: ld)
      yield e
      entry = ldap_next_entry(ld.r, entry)

    cookie = cookieFromMsg(ld, pageSize, msg)
    if cookie == "":
      break

when isMainModule:
  const host = "ldap://ldap.forumsys.com:389"
  const login = "cn=read-only-admin,dc=example,dc=com"
  const pass = "password"

  let ld = newLdap(host)
  ld.saslBind login, pass
  echo ld.whoAmI
  for e in ld.search("(objectclass=*)", pageSize = 5):
    echo e.getDN
  