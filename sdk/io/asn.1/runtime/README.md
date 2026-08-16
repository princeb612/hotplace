### example1

#### Type1 ::= VisibleString

- DER
  - 1A 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL 1A 05 V 4A 6F 6E 65 73
  - node 1 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
- weakly-typed AST
  - NODE1 VisibleString
- strongly-typed AST
  - Type1 referenced type
    - VisibleString

#### Type2 ::= [APPLICATION 3] IMPLICIT Type1

- DER
  - 43 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL 43 05 V 4A 6F 6E 65 73
  - node 1 I 0x40 (APPLICATION) T 3 ([APPLICATION 3]) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [APPLICATION 3]
    - ANY
- strongly-typed AST
  - Type2 referenced type
    - tagged type
      - tag type
        - [APPLICATION 3] IMPLICIT
      - Type1 referenced type
        - VisibleString

#### Type3 ::= [2] EXPLICIT Type2

- DER
  - A2 07 43 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL A2 07
  - node 1 I 0xA0 (CONTEXT+CONSTRUCTED) T 2 ([2]) L 7
    - [x] TL 43 05 V 4A 6F 6E 65 73
    - node 2 I 0x40 (APPLICATION) T 3 ([APPLICATION 3]) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [2] EXPLICIT
    - NODE2 tagged type
      - tag type
        - [APPLICATION 3]
      - ANY
- strongly-typed AST
  - Type3 referenced type
    - tagged type
      - tag type
        - [2] EXPLICIT
      - Type2 referenced type
        - tagged type
          - tag type
            - [APPLICATION 3] IMPLICIT
          - Type1 referenced type
            - VisibleString

#### Type4 ::= [APPLICATION 7] IMPLICIT Type3

- DER
  - 67 07 43 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL 67 07
  - node 1 I 0x60 (APPLICATION+CONSTRUCTED) T 7 ([APPLICATION 7]) L 7
    - [x] TL 43 05 V 4A 6F 6E 65 73
    - node 2 I 0x40 (APPLICATION) T 3 ([APPLICATION 3]) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [APPLICATION 7] EXPLICIT
    - NODE2 tagged type
      - tag type
        - [APPLICATION 3]
      - ANY
- strongly-typed
  - Type4 referenced type
    - tagged type
      - tag type
        - [APPLICATION 7] IMPLICIT
      - Type3 referenced type
        - tagged type
          - tag type
            - [2] EXPLICIT
          - Type2 referenced type
            - tagged type
              - tag type
                - [APPLICATION 3] IMPLICIT
              - Type1 referenced type
                - VisibleString

#### Type5 ::= [2] IMPLICIT Type2

- DER
  - 82 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL 82 05 V 4A 6F 6E 65 73
  - node 1 I 0x80 (CONTEXT) T 2 ([2]) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [2]
    - ANY
- strongly-typed AST
  - Type5 referenced type
    - tagged type
      - tag type
        - [2] IMPLICIT
      - Type2 referenced type
        - tagged type
          - tag type
            - [APPLICATION 3] IMPLICIT
          - Type1 referenced type
            - VisibleString

#### Type6 ::= [2] EXPLICIT Type1

- DER
  - A2 07 1A 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL A2 07
  - node 1 I 0xA0 (CONTEXT+CONSTRUCTED) T 2 ([2]) L 7
    - [x] TL 1A 05 V 4A 6F 6E 65 73
    - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [2] EXPLICIT
    - NODE2 VisibleString
- strongly-typed AST
  - Type6 referenced type
    - tagged type
      - tag type
        - [2] EXPLICIT
      - Type1 referenced type
        - VisibleString

### example2

#### SEQUENCE {name VisibleString, ok BOOLEAN}

- DER
  - 30 0A 1A 05 4A 6F 6E 65 73 01 01 FF
- weakly-typed TLV tree
  - [x] TL 30 0A
  - node 1 I 0x20 (UNIVERSAL+CONSTRUCTED) T 16 (SEQUENCE) L 10
    - [x] TL 1A 05 V 4A 6F 6E 65 73
    - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
    - [x] TL 01 01 V FF
    - node 3 I 0x00 (UNIVERSAL) T 1 (BOOLEAN) L 1
- weakly-typed AST
  - NODE1 SEQUENCE
    - NODE2 VisibleString
    - NODE3 BOOLEAN
- strongly-typed AST
  - SEQUENCE
    - name VisibleString
    - ok BOOLEAN

#### Type1 ::= SEQUENCE {name VisibleString, ok BOOLEAN}

- DER
  - 30 0A 1A 05 4A 6F 6E 65 73 01 01 FF
- weakly-typed TLV tree
  - Type1 referenced type
    - SEQUENCE
      - name VisibleString
      - ok BOOLEAN
- weakly-typed AST
  - [x] TL 30 0A
  - node 1 I 0x20 (UNIVERSAL+CONSTRUCTED) T 16 (SEQUENCE) L 10
    - [x] TL 1A 05 V 4A 6F 6E 65 73
    - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
    - [x] TL 01 01 V FF
    - node 3 I 0x00 (UNIVERSAL) T 1 (BOOLEAN) L 1
- strongly-typed AST
  - NODE1 SEQUENCE
    - NODE2 VisibleString
    - NODE3 BOOLEAN

#### Type2 ::= [APPLICATION 5] IMPLICIT Type1

- DER
  - 65 0A 1A 05 4A 6F 6E 65 73 01 01 FF
- weakly-typed TLV tree
  - [x] TL 65 0A
  - node 1 I 0x60 (APPLICATION+CONSTRUCTED) T 5 ([APPLICATION 5]) L 10
    - [x] TL 1A 05 V 4A 6F 6E 65 73
    - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
    - [x] TL 01 01 V FF
    - node 3 I 0x00 (UNIVERSAL) T 1 (BOOLEAN) L 1
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [APPLICATION 5] IMPLICIT
    - SEQUENCE
      - NODE2 VisibleString
      - NODE3 BOOLEAN
- strongly-typed AST
  - Type2 referenced type
    - tagged type
      - tag type
        - [APPLICATION 5] IMPLICIT
      - Type1 referenced type
        - SEQUENCE
          - name VisibleString
          - ok BOOLEAN
