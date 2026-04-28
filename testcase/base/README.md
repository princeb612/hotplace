#### reference

* test vector
  * modpow
    * https://en.wikipedia.org/wiki/Modular_exponentiation
* reference
  * https://www.calculator.net/big-number-calculator.html

#### YAML schema

* bignumber YAML schema

````
testvector:
  - example: readstring
    schema: BIGNUMBER STRING                # [mandatory] "BIGNUMBER STRING"
    items:
      - hex: hexstring
        desc: decimalstring
  - example: arithmetic_operations
    schema: BIGNUMBER ARITHMETIC            # [mandatory] "BIGNUMBER ARITHMETIC"
    items:
      - int1: decimalstring|hexstring       # [mandatory]
        int2: decimalstring|hexstring       # [mandatory]
        add: decimalstring|hexstring        #
        sub: decimalstring|hexstring        #
        mul: decimalstring|hexstring        #
        div: decimalstring|hexstring        #
        mod: decimalstring|hexstring        #
        lshift1: decimalstring|hexstring    #
        rshift1: decimalstring|hexstring    #
  - example: intminmax
    schema: BIGNUMBER INTMINMAX             # [mandatory] "BIGNUMBER INTMINMAX"
    items:
      - bits: uint32                        # [mandatory]
        intmin: decimalstring|hexstring
        intmax: decimalstring|hexstring
        uintmax: decimalstring|hexstring
  - example: bits_operations
    schema: BIGNUMBER BITWISE               # [mandatory] "BIGNUMBER BITWISE"
    items:
      - int1: decimalstring|hexstring       # [mandatory]
        int2: decimalstring|hexstring       # [mandatory]
        and: decimalstring|hexstring
        or: decimalstring|hexstring
        xor: decimalstring|hexstring
  - example: negative
    schema: BIGNUMBER NEGATIVE              # [mandatory] "BIGNUMBER NEGATIVE"
    items:
      - value: decimalstring|hexstring      # [mandatory]
        expect: decimalstring|hexstring     # [mandatory]
  - example: modpow
    schema: BIGNUMBER MODPOW                # [mandatory] "BIGNUMBER MODPOW"
    items:
      - base: decimalstring|hexstring       # [mandatory]
        exp: decimalstring|hexstring        # [mandatory]
        mod: decimalstring|hexstring        # [mandatory]
        expect: decimalstring|hexstring     # [mandatory]
````

* capacity YAML schema

````
testvector:
  - example: unsigned_byte_capacity
    schema: UNSIGNED BYTE CAPACITY          # [mandatory]
    items:
      - value: decimalstring|hexstring      # [mandatory]
        expect: int                         # [mandatory]
  - example: signed_byte_capacity
    schema: SIGNED BYTE CAPACITY            # [mandatory]
    items:
      - value: decimalstring|hexstring      # [mandatory]
        expect: int                         # [mandatory]
````

* cmdline YAML schema

````
testvector:
  - example: string
    schema: CMDLINE                         # [mandatory] "CMDLINE"
    template: myoption                      # "myoption" MYOPTION structure
    items:
      - item:
        args:                               # [mandatory] 0..5
          - param1
          - param2
          - param3
          - param4
          - param5
        expect: boolean                     # [mandatory]
        reason: string
````

* valist YAML schema

````
testvector:
  - example: string
    schema: VALIST SPRINTF                  # [mandatory] "VALIST SPRINTF"
    args:
      - type: "float"|"string"|"int"        # [mandatory]
        value: string                       # [mandatory]
    items:
      - item:
        format: string                      # [mandatory] value={1} value={2} value={3}
        expect: boolean                     # [mandatory] result
````
