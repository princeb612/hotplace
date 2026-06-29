#### reference

* test vector
  * modpow
    * https://en.wikipedia.org/wiki/Modular_exponentiation
* reference
  * https://www.calculator.net/big-number-calculator.html
  * https://bigcalculator.org/

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
        args:                               # [mandatory] 0..9
          - argv1                           # argv[1]
          - argv2                           # argv[2]
          - argv3                           # argv[3]
          - argv4                           # argv[4]
          - argv5                           # argv[5]
        expect: boolean                     # [mandatory]
        reason: string
````

* valist YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: VALIST                          # [mandatory] "VALIST SPRINTF"
    args:
      - type: "float"|"string"|"int"        # [mandatory]
        value: string                       # [mandatory]
    items:
      - item: string
        format: string                      # [mandatory] value={1} value={2} value={3}
        expect: boolean                     # [mandatory] result
````

* regular expression YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: REGEX                           # [mandatory] "REGEX"
    items:
      - item: string                        #
        input: string                       # [mandatory]
        expr: expression                    # [mandatory]
        results:
        - "string"                          # [mandatory] 0..*
````

* floating point YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: FLOATINGPOINT                   # [mandatory] "FLOATINGPOINT"
    items:
      - float1: string                      # [mandatory] 123.45, -0.00123 1.2e8 1/3 355/113 22/7 ...
        float2: string                      # [mandatory]
        add: string                         #
        sub: string                         #
        mul: string                         #
        div: string                         #
````

* aho corasick YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: AHO CORASICK                    # [mandatory] "AHO CORASICK"
    items:
      - item: string                        # [mandatory]
        input: string                       # [mandatory]
        option: array of option string      # [mandatory] ex. [wildcards, ignorecase]
                                            #             if wildcards option is included, wildcards such as ?, * can be included.
        pattern:                            # [mandatory]
          words: array of range pair        # [mandatory] ex. "words": [[begin1, end1], [begin2, end2], ...]
````

* KMP YAML schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: KMP                             # [mandatory] "KMP"
    items:
      - item: string                        # [mandatory]
        pattern: string                     # [mandatory]
        match: string                       # [mandatory]
          words: array of occurrence        # [mandatory] ex. "words": [pos1, pos2, ...]
````
