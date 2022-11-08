import unittest
import strutils

import nimldap/tinyasn1

test "encode":
  check newAsnInt(33).toHex == "020121"
  check newAsnInt(333).toHex == "0202014D"
  check newAsnString("r".repeat 33).toHex == "0421" & "72".repeat 33
  check newAsnString("r".repeat 333).toHex == "0482014D" & "72".repeat 333
  check newAsnString("r".repeat 3333).toHex == "04820D05" & "72".repeat 3333
  check newPagingValue(7, "").toHex == "30050201070400"
  check newPagingValue(18, "").toHex == "30050201120400"
  check newPagingValue(5000, "abc").toHex == "3009020213880403616263"
  check newPagingValue(5000, "r".repeat 5000).toHex == "308213900202138804821388" & "72".repeat 5000

test "decode":
  check newPagingValue(7, "").readPagingValues == (7, "")
  check newPagingValue(18, "").readPagingValues == (18, "")
  check newPagingValue(5000, "abc").readPagingValues == (5000, "abc")
  check newPagingValue(5000, "r".repeat 5000).readPagingValues == (5000, "r".repeat 5000)
