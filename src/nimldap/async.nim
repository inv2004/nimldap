import bindings
import shared except Entry

export LdapAsyncRef, EntryAsync, dn, attrs, `$`, `[]`, `{}`, len,
    LdapException, unbind, items, pairs, attrs, values, pretty,
    sid,
    LdapScope, newCtrl, newPagingCtrl, Extension

import std/strutils
import std/asyncdispatch

const defaultAsyncSleepMs = 10

# proc search*(ld: LdapASyncRef, filter: string, attrs: openArray[string] = ["*"],
#     scope = LdapScope.SubTree, base = rootDC,
#     limit = 0, ctrls: openArray[Ctrl] = [], pageSize = 0, pageCookie = ""): SearchRef =


type
  SearchObjRef = ref object
    ld: LdapAsyncRef
    msgId: int
    msg: LdapMessageRef
    filter: string
    attrs: seq[string]
    scope: LdapScope
    base: string
    limit: int
    ctrls: seq[Ctrl]
    pageSize: int

proc newLdapAsync*(url: string): LdapAsyncRef =
  new(result)
  checkErr ldap_initialize(result.r, url.cstring)
  result.setOption(LDAP_OPT_PROTOCOL_VERSION, LdapVersion.V3)
  result.setOption(LDAP_OPT_NETWORK_TIMEOUT, defaultNetworkTimeout)

proc waitResult(ld: LdapAsyncRef, msgId: int, waitForAll = false): Future[(
    LdapMessageRef, int)] {.async.} =
  let msg = LdapMessageRef()
  var t = Timeval(sec: 0, nano: 0)
  var err = 0
  while err == 0:
    err = ldap_result(ld.r, msgId, waitForAll.int, t.addr, msg)
    # echo err.toHex
    if err == 0:
      await sleepAsync defaultAsyncSleepMs
  return (msg, err)

proc saslBind*(ld: LdapAsyncRef, login, pass: string, dc = rootDC): Future[
    void] {.async.} =
  var msgId: int
  let creds = newBer(pass)
  checkErr ldap_sasl_bind(ld.r, login.cstring, LDAP_SASL_SIMPLE, creds, nil,
      nil, msgId)
  let (msg, _) = await waitResult(ld, msgId)
  checkErr ldap_parse_sasl_bind_result(ld.r, msg.r, nil, 0)
  ld.base = if dc == rootDC: extractDC login else: dc

proc whoAmI*(ld: LdapAsyncRef): Future[string] {.async.} =
  var msgId: int
  checkErr ldap_whoami(ld.r, nil, nil, msgId)
  let (msg, _) = await ld.waitResult(msgId)
  var auth: Ber
  checkErr ldap_parse_whoami(ld.r, msg.r, auth)
  return $auth.r[]

proc search*(ld: LdapASyncRef, filter: string, attrs: openArray[string] = ["*"],
    scope = LdapScope.SubTree, base = rootDC,
    limit = 0, ctrls: openArray[Ctrl] = [], pageSize = 0,
        pageCookie = ""): SearchObjRef =
  let base = if base == rootDC: ld.base else: base
  var msgId: int
  let attrsC = allocCStringArray(attrs)
  defer: deallocCStringArray(attrsC)
  let ctrlsLocal = newCtrlsWithPage(ctrls, pageSize, pageCookie)
  checkErr ldap_search_ext(ld.r, base.cstring, scope.int,
      filter, attrsC, 0, ctrlsLocal.r, nil, nil, limit, msgId)
  SearchObjRef(ld: ld, msgId: msgId, filter: filter, attrs: @attrs, scope: scope,
      base: base, limit: limit, ctrls: @ctrls, pageSize: pageSize)

proc next*(s: SearchObjRef): Future[EntryAsync] {.async.} =
  while true:
    let (msg, err) = await s.ld.waitResult(s.msgId)
    if err == 0x65:
      let cook = cookieFromMsg(s.ld, s.pageSize, msg)
      if cook != "":
        let nextSearch = s.ld.search(s.filter, s.attrs, LdapScope.SubTree,
            s.base, 0, s.ctrls, s.pageSize, cook)
        s.msgId = nextSearch.msgId
      else:
        return EntryAsync(done: true)
    else:
      let entry = ldap_first_entry(s.ld.r, msg.r)
      return EntryAsync(entry: entry, ld: s.ld, msg: msg, done: false)

proc count*(ld: LdapAsyncRef, filter: string, scope = LdapScope.SubTree,
    base = rootDC, limit = 0, pageSize = 0): Future[int] {.async.} =
  var cookie = ""
  while true:
    let search = ld.search(filter, ["cn"], scope, base, limit, [], pageSize, cookie)
    let (msg, _) = await ld.waitResult(search.msgId, waitForAll = true)
    result += ldap_count_entries(ld.r, msg.r)
    if pageSize > 0:
      cookie = cookieFromMsg(ld, pageSize, msg)
    if cookie == "":
      break
