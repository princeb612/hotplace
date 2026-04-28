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
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER STRING                # [mandatory] "BIGNUMBER STRING"
    items:
      - hex: hexstring
        desc: decimalstring
  - example: string                         # [mandatory] testcase
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
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER INTMINMAX             # [mandatory] "BIGNUMBER INTMINMAX"
    items:
      - bits: uint32                        # [mandatory]
        intmin: decimalstring|hexstring
        intmax: decimalstring|hexstring
        uintmax: decimalstring|hexstring
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER BITWISE               # [mandatory] "BIGNUMBER BITWISE"
    items:
      - int1: decimalstring|hexstring       # [mandatory]
        int2: decimalstring|hexstring       # [mandatory]
        and: decimalstring|hexstring
        or: decimalstring|hexstring
        xor: decimalstring|hexstring
  - example: string                         # [mandatory] testcase
    schema: BIGNUMBER NEGATIVE              # [mandatory] "BIGNUMBER NEGATIVE"
    items:
      - value: decimalstring|hexstring      # [mandatory]
        expect: decimalstring|hexstring     # [mandatory]
  - example: string                         # [mandatory] testcase
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
  - example: string                         # [mandatory] testcase
    schema: UNSIGNED BYTE CAPACITY          # [mandatory] "UNSIGNED BYTE CAPACITY"
    items:
      - value: decimalstring|hexstring      # [mandatory]
        expect: int                         # [mandatory]
  - example: string                         # [mandatory] testcase
    schema: SIGNED BYTE CAPACITY            # [mandatory] "SIGNED BYTE CAPACITY"
    items:
      - value: decimalstring|hexstring      # [mandatory]
        expect: int                         # [mandatory]
````

* cmdline YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: CMDLINE                         # [mandatory] "CMDLINE"
    template: myoption                      # [mandatory] "myoption" MYOPTION structure
    items:
      - item: string
        args:                               # [mandatory] 0..5
          - param1: string
          - param2: string
          - param3: string
          - param4: string
          - param5: string
        expect: boolean                     # [mandatory]
        reason: string
````

* valist YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: VALIST SPRINTF                  # [mandatory] "VALIST SPRINTF"
    args:
      - type: "float"|"string"|"int"        # [mandatory]
        value: string                       # [mandatory]
    items:
      - item: string
        format: string                      # [mandatory] value={1} value={2} value={3}
        expect: boolean                     # [mandatory] result
````
