import stew/endians2
import bitops
import streams
import bindings

proc beLen[T: static[int]](be: array[T, byte]): int =
  var len0 = 0
  for x in be:
    if x == 0:
      inc len0
    else:
      break
  be.len - len0

proc genLen(len: int): string =
  if len < 0x80:
    result.add len.char
  else:
    let bb = len.uint64.toBytesBE
    let lenlen = bb.beLen
    result.add char(0x80 or lenlen.byte)
    for x in bb[^lenlen..^1]: result.add x.char

proc newAsnInt*(size: uint32): string =
  result.add '\x02'
  let be = size.toBytesBE
  let len = be.beLen
  result.add genLen(len)
  for x in be[^len..^1]: result.add x.char

proc newAsnString*(s: string): string =
  result.add '\x04'
  result.add genLen(s.len)
  result.add s

proc newPagingValue*(size: int, cookie: string): string =
  result.add "\x30"
  let i = newAsnInt(size.uint32)
  let s = newAsnString(cookie)
  result.add genLen((i.len + s.len))
  result.add i
  result.add s

proc getLen*(be: openArray[byte]): (int, int) =
  if not be[1].testBit(7):
    return (be[1].int, 1)
  else:
    let lenlen = int(be[1] and 0x7F)
    for i in 2..<2+lenlen:
      result[0] = 256*result[0] + be[i].int
    result[1] = 1+lenlen

proc readLen(s: StringStream): int =
  let len0 = s.readUint8
  if len0.testBit(7):
    let lenlen = int(len0 and 0x7F)
    for _ in 0..<lenlen:
      result = result * 256 + s.readUint8.int
  else:
    return len0.int

proc inSeq*(s: StringStream) =
  doAssert s.readUint8 == 0x30
  discard s.readLen()

proc readInt*(s: StringStream): int =
  doAssert s.readUint8 == 0x02
  let len = s.readLen()
  for _ in 0..<len:
    result = result * 256 + s.readUint8.int

proc readString*(s: StringStream): string =
  doAssert s.readUint8 == 0x04
  let len = s.readLen()
  s.readStr(len)

proc readPagingValues*(s: string): (int, string) =
  let s = newStringStream s
  s.inSeq()
  result[0] = s.readInt()
  result[1] = s.readString()

proc readCook*(b: ptr CtrlInt): string =
  let s = newStringStream $b.val
  s.inSeq()
  discard s.readInt()
  s.readString()

