#### study

* Strongly-Typed
  * semantic
  * grammatical
  * EXPLICIT is a type modifier
* Weakly-Typed
  * structural
  * encoding layout
  * the CONSTRUCTED bit indicates the TLV container

#### Type2 ::= [APPLICATION 5] IMPLICIT Type1

65 0A 1A 05 4A 6F 6E 65 73 01 01 FF

- [x] TL 65 0A
- node 1 I 0x60 (APPLICATION+CONSTRUCTED) T 5 ([APPLICATION 5]) L 10
  - [x] TL 1A 05 V 4A 6F 6E 65 73
  - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
  - [x] TL 01 01 V FF
  - node 3 I 0x00 (UNIVERSAL) T 1 (BOOLEAN) L 1

#### Type4 ::= [3] EXPLICIT Type3

A3 0B A2 09 A1 07 1A 05 4A 6F 6E 65 73

- [x] TL A3 0B
- node 1 I 0xA0 (CONTEXT+CONSTRUCTED) T 3 ([3]) L 11
  - [x] TL A2 09
  - node 2 I 0xA0 (CONTEXT+CONSTRUCTED) T 2 ([2]) L 9
    - [x] TL A1 07
    - node 3 I 0xA0 (CONTEXT+CONSTRUCTED) T 1 ([1]) L 7
      - [x] TL 1A 05 V 4A 6F 6E 65 73
      - node 4 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5

#### Type1 ::= [APPLICATION 128] IMPLICIT INTEGER

5f 81 00 01 00

- [x] TL 5F 81 00 01 V 00
- node 1 I 0x40 (APPLICATION) T 128 ([APPLICATION 128]) L 1
