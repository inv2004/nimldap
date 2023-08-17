import bindings
import shared
import tinyasn1
import sequtils

type SearchObj = object
  ld: LdapRef
  filter: string
  attrs: seq[string]
  scope: LdapScope
  base: string
  limit: int
  ctrls: seq[Ctrl]
  pageSize: int

export LdapRef, EntryAsync, dn, attrs, `$`, `[]`, `{}`, len,
    LdapException, unbind, items, pairs, attrs, values, pretty,
    sid,
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

proc searchMsg*(self: SearchObj, pageCookie = "", voidAttrs: bool): LdapMessageRef =
  let base = if self.base == rootDC: self.ld.base else: self.base
  let attrsC = allocCStringArray(if voidAttrs: @[] else: self.attrs)
  defer: deallocCStringArray(attrsC)
  let ctrls = newCtrlsWithPage(self.ctrls, self.pageSize, pageCookie)
  let msg = LDAPMessageRef()

  checkErr ldap_search_ext_s(self.ld.r, base.cstring, self.scope.int,
      self.filter.cstring, attrsC, 0, ctrls.r, nil, nil, self.limit, msg)

  return msg

proc search*(ld: LdapRef, filter: string, attrs: openArray[string] = ["*"],
    scope = LdapScope.SubTree, base = rootDC, limit = 0, ctrls: openArray[
        Ctrl] = [], pageSize = 0): SearchObj =
  SearchObj(
    ld: ld,
    filter: filter,
    attrs: toSeq[attrs],
    scope: scope,
    base: base,
    limit: limit,
    ctrls: toSeq[ctrls],
    pageSize: pageSize
  )

proc count*(s: SearchObj): int =
  var cookie = ""
  while true:
    let msg = s.searchMsg(cookie, true)
    result += ldap_count_entries(s.ld.r, msg.r)
    cookie = cookieFromMsg(s.ld, s.pageSize, msg)
    if cookie == "":
      break

proc count*(ld: LdapRef, filter: string, scope = LdapScope.SubTree,
    base = rootDC, limit = 0, pageSize = 0): int =
  ld.search(filter, [], scope, base, limit, [], pageSize).count()

iterator items*(s: SearchObj): Entry =
  var cookie = ""
  let ld = s.ld
  while true:
    let msg = s.searchMsg(cookie, false)

    var entry = ldap_first_entry(ld.r, msg.r)
    while entry != nil:
      let e = Entry(entry: entry, msg: msg, ld: ld)
      yield e
      entry = ldap_next_entry(ld.r, entry)

    cookie = cookieFromMsg(ld, s.pageSize, msg)
    if cookie == "":
      break

iterator pairs*(s: SearchObj): (int, Entry) =
  var i = 0
  for e in s:
    yield (i, e)
    inc i

when isMainModule:
  const host = "ldap://ldap.forumsys.com:389"
  const login = "cn=read-only-admin,dc=example,dc=com"
  const pass = "password"

  let ld = newLdap(host)
  ld.saslBind login, pass
  echo ld.whoAmI
  for e in ld.search("(objectclass=*)", pageSize = 5):
    echo e.dn
