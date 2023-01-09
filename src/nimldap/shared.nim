import bindings
import tinyasn1

import strutils

type
  Ldap* = object
    r*: ptr LdapInt
    base*: string
  LdapRef* = ref Ldap

  LdapAsync* = object
    r*: ptr LdapInt
    base*: string
  LdapAsyncRef* = ref LdapAsync

  Entry* = ref object
    entry*: EntryInt
    msg*: LdapMessageRef
    ld*: LdapRef

  EntryAsync* = ref object
    entry*: EntryInt
    msg*: LdapMessageRef
    ld*: LdapAsyncRef
    done*: bool

  Ctrl* = object
    oid*: string
    val*: string
    isCritical*: bool

  AnyEntry = Entry | EntryAsync

  LdapException* = object of ValueError
    errCode*: int

const defaultNetworkTimeout* = 2
const rootDC* = "/"

type
  Extension* = enum
    LDAP_SERVER_NOTIFICATION_OID = "1.2.840.113556.1.4.528"
    LDAP_PAGED_RESULT_OID_STRING = "1.2.840.113556.1.4.319"

proc `=destroy`(x: var Ldap) =
  if x.r != nil:
    discard ldap_unbind_ext_s(x.r, nil, nil)
  `=destroy`(x.base)

proc `=destroy`(x: var LdapAsync) =
  if x.r != nil:
    discard ldap_unbind_ext_s(x.r, nil, nil)
  `=destroy`(x.base)

proc newLdapException*(err: int, msg = ""): ref LdapException =
  new(result)
  result.errCode = err
  result.msg = msg & " with error code " & $err

template checkErr*(body: untyped): untyped =
  let err = body
  if err != 0:
    raise newLdapException(err, "ldap failed")

proc setOption*(ld: LdapRef|LdapAsyncRef, opt: LdapOption, value: int) =
  var val = value.int
  checkErr ldap_set_option(ld.r, opt, val.addr)

proc setOption*(ld: LdapRef|LdapAsyncRef, opt: LdapOption, value: LdapVersion) =
  ld.setOption(opt, value.int)

proc extractDC*(login: string): string =
  let lcLogin = login.toLowerAscii
  if lcLogin.find"dc=" >= 0:
    for p in lcLogin.split ",":
      if p.startsWith "dc=":
        if result.len > 0: result.add ","
        result.add p
  else:
    let emailParts = lcLogin.split '@'
    let domain = emailParts[^1]
    for p in domain.split ".":
      if result.len > 0: result.add ","
      result.add "dc="&p

proc unbind*(ld: LdapRef|LdapAsyncRef) =
  checkErr ldap_unbind_ext_s(ld.r, nil, nil)
  ld.r = nil

proc getDN*(e: AnyEntry): string =
  $ldap_get_dn(e.ld.r, e.entry)

proc `[]`*(e: AnyEntry, attr: string): string =
  let vals = ldap_get_values_len(e.ld.r, e.entry, attr.cstring)
  if vals.r == nil:
    raise newException(KeyError, "key not found: " & attr)
  var val = vals[result.len]
  if val != nil:
    result = $val[]

proc `{}`*(e: AnyEntry, attr: string): seq[string] =
  let vals = ldap_get_values_len(e.ld.r, e.entry, attr.cstring)
  if vals.r == nil:
    raise newException(KeyError, "key not found: " & attr)
  var val = vals[result.len]
  while val != nil:
    result.add $val[]
    val = vals[result.len]

iterator items*(e: AnyEntry): string =
  var berElem: BerElement
  var attr = ldap_first_attribute(e.ld.r, e.entry, berElem)
  while attr.r != nil:
    yield $attr
    attr = ldap_next_attribute(e.ld.r, e.entry, berElem)

iterator pairs*(e: AnyEntry): (string, BerArrRef) =
  var berElem: BerElement
  var attr = ldap_first_attribute(e.ld.r, e.entry, berElem)
  while attr.r != nil:
    let vals = BerArrRef()
    vals[] = ldap_get_values_len(e.ld.r, e.entry, attr.r)
    yield ($attr, vals)
    attr = ldap_next_attribute(e.ld.r, e.entry, berElem)

iterator items*(vals: BerArrRef): string =
  var idx = 0
  var val = vals[idx]
  while val != nil:
    yield $val[]
    inc idx
    val = vals[idx]

proc len*(vals: BerArrRef): int =
  ldapCountValuesLen(nil, vals)

proc attrs*(e: AnyEntry): seq[string] =
  var ber: BerElement
  var attr = ldap_first_attribute(e.ld.r, e.entry, ber)
  while attr.r != nil:
    result.add $attr
    attr = ldap_next_attribute(e.ld.r, e.entry, ber)

proc values*(vals: BerArrRef): seq[string] =
  var val = vals[result.len]
  while val != nil:
    result.add $val[]
    val = vals[result.len]

proc `$`*(vals: BerArrRef): string =
  $values(vals)

proc newCtrl*(oid: string|Extension, val = "", isCritical = true): Ctrl =
  Ctrl(oid: $oid, val: val, isCritical: isCritical)

proc newControls*(ctrls: openArray[Ctrl]): CtrlArr =
  if ctrls.len == 0:
    return

  result.r = cast[ptr UncheckedArray[ptr CtrlInt]](alloc0((ctrls.len+1) *
      sizeof(ptr CtrlInt)))

  for i, ctrl in ctrls:
    let val = newBer(ctrl.val)
    checkErr ldap_control_create(ctrl.oid.cstring, ctrl.isCritical.int, val, 1,
        result.r[i])

proc newPagingCtrl*(size: int, cookie: string): Ctrl =
  newCtrl(LDAP_PAGED_RESULT_OID_STRING, newPagingValue(size, cookie))

proc newCtrlsWithPage*(ctrls: openArray[Ctrl], pageSize: int,
    cookie: string): CtrlArr =
  if pageSize > 0:
    newControls(@ctrls & newPagingCtrl(pageSize, cookie))
  else:
    newControls(ctrls)

proc cookieFromMsg*(ld: LdapRef|LdapAsyncRef, pageSize: int,
    msg: LdapMessageRef): string =
  if pageSize == 0:
    return
  var errcode = 0
  var ctrls = CtrlArr()
  checkErr ldap_parse_result(ld.r, msg.r, errcode, nil, nil, nil, ctrls.r, 0)
  var i = 0
  while ctrls.r[i] != nil:
    if $LDAP_PAGED_RESULT_OID_STRING == $ctrls.r[i].oid:
      return readCook(ctrls.r[0])
    inc i

