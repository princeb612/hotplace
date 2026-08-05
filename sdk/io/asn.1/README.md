#### references

* Gemini recommended
  * books
    * ASN.1 - Communication between Heterogeneous Systems - Olivier Dubuisson
      * [ASN.1 - Communication between Heterogeneous Systems](https://www.oss.com/asn1_runtime/resources/books-whitepapers-pubs/dubuisson-asn1_runtime-book.PDF)
    * A Layman's Guide to a Subset of ASN.1, BER, and DER - Burton S. Kaliski
      * [A Layman's Guide to a Subset of ASN.1, BER, and DER](https://luca.ntop.org/Teaching/Appunti/asn1_runtime.html)
    * ASN.1 Complete - John Larmouth

* ChatGPT recommended
  * online
    * https://www.oss.com/asn1_runtime/resources/asn1_runtime-made-simple/asn1_runtime-quick-reference.html
    * https://obj-sys.com/asn1tutorial/index.php
  * RFCs
    * RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
    * RFC 5652 Cryptographic Message Syntax (CMS)
    * RFC 5912 New ASN.1 Modules for the Public Key Infrastructure Using X.509 (PKIX)

* etc.
  * [ASN.1 by simple words](https://www.strozhevsky.com/free_docs/asn1_by_simple_words.pdf)
  * RFC 2986 PKCS #10: Certification Request Syntax Specification Version 1.7
  * X.680-X.693 : Information Technology - Abstract Syntax Notation One (ASN.1) & ASN.1 encoding rules
    * https://www.itu.int/rec/T-REC-X.680-X.693-202102-I/en
    * Recommendation X.680-X.693 (02/21)
  * ASN.1 (Abstract Syntax Notation One) is the international standard for representing data types and structures.
    * ITU-T X.680 ISO/IEC 8824-1 Abstract Syntax Notation One (ASN.1): Specification of basic notation
    * ITU-T X.681 ISO/IEC 8824-2 Abstract Syntax Notation One (ASN.1): Information object specification
    * ITU-T X.682 ISO/IEC 8824-3 Abstract Syntax Notation One (ASN.1): Constraint specification
    * ITU-T X.683 ISO/IEC 8824-4 Abstract Syntax Notation One (ASN.1): Parameterization of ASN.1 specifications
    * ITU-T X.690 ISO/IEC 8825-1 ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
      * X.690 8 Basic encoding rules
      * X.690 9 Canonical Encoding Rules
      * X.690 10 Distinguished encoding rules
      * X.690 11 Restrictions on BER employed by both CER and DER
    * ITU-T X.691 ISO/IEC 8825-2 ASN.1 encoding rules: Specification of Packed Encoding Rules (PER)
    * ITU-T X.692 ISO/IEC 8825-3 ASN.1 encoding rules: Specification of Encoding Control Notation (ECN)
    * ITU-T X.693 ISO/IEC 8825-4 ASN.1 encoding rules: XML Encoding Rules (XER)

#### sketch overview

- [ ] asn.1/basic
  - [ ] asn.1/basic/semantic
    - asn1_object
      - asn1_tag
      - asn1_type
        - asn1_builtin_type
          - asn1_boolean
          - asn1_integer
          - asn1_bitstring
          - ...
        - asn1_tagged_type
        - asn1_referenced_type
        - asn1_container
          - asn1_sequence
          - asn1_set
          - asn1_choice
        - asn1_container_of
          - asn1_sequence_of
          - asn1_set_of
        - asn1_enum
    - [ ] asn.1/basic/semantic/constraints
      - asn1_constraint
        - asn1_constraint_single
        - asn1_constraint_size
        - asn1_constraint_range
        - asn1_constraint_from
        - asn1_constraint_pattern
  - [ ] asn.1/basic/structural
    - asn1_node
      - asn1_constructed_node
      - asn1_primitive_node
  - [ ] asn.1/basic/visitor
    - asn1_visitor
      - asn1_ast_visitor
      - asn1_notation_visitor
      - asn1_der_visitor
- [ ] asn.1/runtime
  - asn1_runtime
  - asn1_weakly_typed
  - asn1_stronly_typed
