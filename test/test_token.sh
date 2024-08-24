#!/bin/sh

# test tokenisation

# set -x
# set -e

# args are:
#   string-to-parse
#   expected-token
#   expected-string (for string tokens)
#   expected-residual
check() {
  test_name="$1"
  test_string="$2"
  residual="$3"
  token="$4"
  token_string="$5"

  echo -n "$test_name ..."
  log=$(./test_token "$2" "$3" "$4" "$5")
  if [ $? -ne 0 ]; then
    echo " FAIL"
    echo "./test_token '$2' '$3' '$4' '$5'"
    echo $log
    exit 1
  else
    echo " yes"
  fi
}

check "quoted strings end on the closing quote" \
    '"ab"cd,abc,ab' 3 'ab' 'cd,abc,ab'

check "quoted strings can have escaped quotes" \
    '"ab\"cd",abc,ab' 3 'ab"cd' ',abc,ab'

check "no closing quote" \
    '"  abcd  ,abc,ab' 3 '  abcd  ,abc,ab' ''

check "empty quote" \
    '""abcd,abc,ab' 3 '' 'abcd,abc,ab'

check "skip whitespace around quoted strings" \
    '  "  abcd "  ,abc,ab' 3 '  abcd ' '  ,abc,ab'

check "unquoted strings can have embedded quotes" \
    'ab"cd,abc,ab' 3 'ab"cd' ',abc,ab'

check "skip whitespace around unquoted strings" \
    '  abcd  ,abc,ab' 3 'abcd' ',abc,ab'

