const libLdap = "libldap.so"
const libLber = "liblber.so"

const LDAP_SASL_SIMPLE* = nil

type
  LdapVersion* = enum
    V3 = 3

  LdapOption* = enum
    LDAP_OPT_PROTOCOL_VERSION = 0x0011
    LDAP_OPT_NETWORK_TIMEOUT = 0x5005

  LdapScope* = enum
    Base = 0
    OneLevel = 1
    SubTree = 2

  LdapInt* = object

  LdapMessageInt* = object
  EntryInt* = ptr LdapMessageInt
  LdapMessage* = object
    r*: ptr LdapMessageInt
  LdapMessageRef* = ref LdapMessage

  BerInt* = object
    len*: uint32
    data*: cstring
  BerPtr* = ptr BerInt
  Ber* = object
    r*: BerPtr

  BerArr* = object
    r*: ptr UncheckedArray[BerPtr]
  BerArrRef* = ref BerArr

  BerElementInt* = object
  BerElement* = object
    r*: ptr BerElementInt

  Timeval* = object
    sec*, nano*: uint32

  LdapString* = object
    r*: cstring

  CtrlInt* = object
    oid*: cstring
    val*: BerInt
    isCritical*: char
  CtrlArr* = object
    r*: ptr UncheckedArray[ptr CtrlInt]
  CtrlArrRef* = ref object

proc `[]`*(x: BerArr|BerArrRef, i: int): ptr BerInt =
  x.r[i]

proc newBer*(s: string): ref BerInt =
  new(result)
  result.len = s.len.uint32
  result.data = s.cstring

func `$`*(ber: BerInt): string =
  if ber.len == 0:
    return ""
  result = newString(ber.len)
  copyMem(result[0].addr, ber.data, ber.len)

func `$`*(lstr: LdapString): string =
  $lstr.r

proc ldap_initialize*(ld: var ptr LdapInt, url: cstring): int {.cdecl,
    dynlib: libLdap, importc: "ldap_initialize".}
proc ldap_memfree*(p: cstring) {.cdecl, dynlib: libLdap,
    importc: "ldap_memfree".}
proc ldap_msgfree*(p: ptr LdapMessageInt) {.cdecl, dynlib: libLdap,
    importc: "ldap_msgfree".}
proc ldap_value_free_len*(p: pointer) {.cdecl, dynlib: libLdap,
    importc: "ldap_value_free_len".}
proc ldap_set_option*(ld: ptr LdapInt, opt: LdapOption, val: ptr int):
    int {.cdecl, dynlib: libLdap, importc: "ldap_set_option".}
proc ldap_sasl_bind_s*(ld: ptr LdapInt, dn: cstring, mechanism: cstring,
    credC: ref BerInt, s, c: typeof(nil), credS: ptr ref BerInt): int {.cdecl,
    dynlib: libLdap, importc: "ldap_sasl_bind_s".}
proc ldap_sasl_bind*(ld: ptr LdapInt, dn: cstring, mechanism: cstring,
    credC: ref BerInt, s, c: typeof(nil), msgId: var int): int {.cdecl,
    dynlib: libLdap, importc: "ldap_sasl_bind".}
proc ldap_parse_sasl_bind_result*(ld: ptr LdapInt, msg: EntryInt,
    servercredp: typeof(nil), freeit: int): int {.cdecl,

dynlib: libLdap, importc: "ldap_parse_sasl_bind_result".}
proc ldap_unbind_ext_s*(ld: ptr LdapInt, s, c: typeof(nil)): int {.cdecl,
    dynlib: libLdap, importc: "ldap_unbind_ext_s".}
proc ldap_whoami_s*(ld: ptr LdapInt, auth: var BerPtr, s, c: typeof(
    nil)): int {.cdecl, dynlib: libLdap, importc: "ldap_whoami_s".}
proc ldap_whoami*(ld: ptr LdapInt, s, c: typeof(
    nil), msgId: var int): int {.cdecl, dynlib: libLdap,
        importc: "ldap_whoami".}
proc ldap_parse_whoami*(ld: ptr LdapInt, msg: EntryInt, auth: var Ber): int
  {.cdecl, dynlib: libLdap, importc: "ldap_parse_whoami".}
proc ldap_result*(ld: ptr LdapInt, msgId: int, all: int, timeout: ptr Timeval,
    res: LdapMessageRef): int
  {.cdecl, dynlib: libLdap, importc: "ldap_result".}
proc ldap_search_ext_s*(ld: ptr LdapInt, base: cstring, scope: int,
    filter: cstring, attrs: pointer, attrsOnly: int, s,
        c: ptr UncheckedArray[ptr CtrlInt], timeout: typeof(nil),
    sizeLimit: int, res: LdapMessageRef): int {.cdecl, dynlib: libLdap,
        importc: "ldap_search_ext_s".}    # TODO: not sure about res: ref here
proc ldap_search_ext*(ld: ptr LdapInt, base: cstring, scope: int,
    filter: cstring, attrs: pointer, attrsOnly: int, s,
        c: ptr UncheckedArray[ptr CtrlInt], timeout: typeof(nil),
    sizeLimit: int, msgId: var int): int {.cdecl, dynlib: libLdap,
        importc: "ldap_search_ext".}
proc ldap_count_entries*(ld: ptr LdapInt, res: EntryInt): int {.cdecl,
    dynlib: libLdap, importc: "ldap_count_entries".}
proc ldap_first_entry*(ld: ptr LdapInt, res: EntryInt): EntryInt {.cdecl,
    dynlib: libLdap, importc: "ldap_first_entry".}
proc ldap_next_entry*(ld: ptr LdapInt, res: EntryInt): EntryInt {.cdecl,
    dynlib: libLdap, importc: "ldap_next_entry".}
proc ldap_get_dn*(ld: ptr LdapInt, res: ptr LdapMessageInt): LdapString {.cdecl,
    dynlib: libLdap, importc: "ldap_get_dn".}
proc ldap_msgtype*(ld: ptr LdapInt, res: ptr LdapMessageInt): int {.cdecl,
    dynlib: libLdap, importc: "ldap_msgtype".}
proc ldap_first_attribute*(ld: ptr LdapInt, entry: ptr LdapMessageInt,
    ber: var BerElement): LdapString {.cdecl, dynlib: libLdap,
    importc: "ldap_first_attribute".}
proc ldap_next_attribute*(ld: ptr LdapInt, res: ptr LdapMessageInt,
    ber: BerElement): LdapString {.cdecl, dynlib: libLdap,
    importc: "ldap_next_attribute".}
proc ldap_get_values_len*(ld: ptr LdapInt, res: ptr LdapMessageInt,
    attrName: cstring): BerArr {.cdecl, dynlib: libLdap,
    importc: "ldap_get_values_len".}
# proc ldap_count_values_len(ld: ptr LDAPInt, val: pointer): int {.cdecl,
#     dynlib: libName, importc: "ldap_count_values_len".}
#     ^^^ BUGGY in openldap
proc ldapCountValuesLen*(ld: ptr LdapInt, vals: BerArr|BerArrRef): int =
  var val = vals.r[result]
  while val != nil:
    inc result
    val = vals[result]

#  int ldap_parse_result( LDAP *ld, LDAPMessage *result,
#       int *errcodep, char **matcheddnp, char **errmsgp,
#       char ***referralsp, LDAPControl ***serverctrlsp,
#       int freeit )
proc ldap_parse_result*(ld: ptr LdapInt, msg: ptr LdapMessageInt, errcodep: var int,
    matcheddnp, errmsgp, referralsp: typeof(nil), serverctrlsp: var ptr UncheckedArray[ptr CtrlInt],
        freeit: int): int {.cdecl,
    dynlib: libLdap, importc: "ldap_parse_result".}

# int ldap_control_create(const char *oid, int iscritical, struct berval *value, int dupval, LDAPControl **ctrlp);
proc ldap_control_create*(oid: cstring, iscritical: int, berval: ref BerInt, dupval: int, ctrlp: var ptr CtrlInt): int
    {.cdecl, dynlib: libLdap, importc: "ldap_control_create".}

proc ldap_controls_free*(ctrls: ptr UncheckedArray[ptr CtrlInt]) {.cdecl,
    dynlib: libLdap, importc: "ldap_controls_free".}

# proc ldap_control_free*(ctrl: ptr CtrlInt) {.cdecl,
#     dynlib: libLdap, importc: "ldap_control_free".}

# LDAPControl **ldap_controls_dup(LDAPControl **ctrls);
proc ldap_controls_dup*(ctrls: ptr UncheckedArray[ptr CtrlInt]): ptr UncheckedArray[ptr CtrlInt] {.cdecl,
    dynlib: libLdap, importc: "ldap_controls_dup".}

proc ber_bvfree*(ber: BerPtr) {.cdecl, dynlib: libLber, importc: "ber_bvfree".}
proc ber_free*(ber: BerElement, freebuf: int) {.cdecl, dynlib: libLber,
    importc: "ber_free".}

proc `=destroy`(x: var LdapString) =
  # echo "lets free ber: ", cast[int](x.r.addr)
  ldap_memfree(x.r)

proc `=destroy`(x: var Ber) =
  # echo "lets free ber: ", cast[int](x.r.addr)
  ber_bvfree(x.r)

proc `=destroy`(x: var LdapMessage) =
  # echo "lets free msg"
  ldap_msgfree(x.r)

proc `=destroy`(x: var BerArr) =
  # echo "lets free berArr: ", cast[int](x.r)
  ldap_value_free_len(x.r)

proc `=destroy`(x: var BerElement) =
  # echo "lets free berElement: ", cast[int](x.addr)
  ber_free(x, 0)

proc `=destroy`(x: var CtrlArr) =
  # echo "lets free CtrlArr"
  ldap_controls_free(x.r) # checks null internally
