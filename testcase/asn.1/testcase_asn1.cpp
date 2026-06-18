/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_asn1.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

// X.690 8.1.2.3 Figure 3 - Identifier octet (low tag number)
// X.690 8.1.2.4.5 Figure 4 - Identifier octet (high tag number)
void test_x690_8_1_2_identifier_octects() {
    _test_case.begin("ITU-T X.690 8.1.2");

    // ChatGPT test vector
    struct testvector {
        bool ispositive;
        uint8 ident;
        uint64 tag;
        const char* notation;
        const char* der;
    } table[] = {
        // 8.1.2.4
        {true, asn1_class_universal | asn1_tag_primitive, asn1_tag_boolean, "BOOLEAN", "01"},
        {true, asn1_class_universal | asn1_tag_primitive, asn1_tag_integer, "INTEGER", "02"},
        {true, asn1_class_universal | asn1_tag_primitive, asn1_tag_octstring, "OCTET STRING", "04"},
        {true, asn1_class_universal | asn1_tag_primitive, asn1_tag_null, "NULL", "05"},
        {true, asn1_class_universal | asn1_tag_primitive, asn1_tag_objid, "OBJECT IDENTIFIER", "06"},
        {true, asn1_class_universal | asn1_tag_constructed, asn1_tag_sequence, "SEQUENCE", "30"},  // 0x20 | 0x10
        {true, asn1_class_universal | asn1_tag_constructed, asn1_tag_set, "SET", "31"},            // 0x20 | 0x11
        {true, asn1_class_context | asn1_tag_primitive, 0, "[0]", "80"},
        {true, asn1_class_context | asn1_tag_primitive, 1, "[1]", "81"},
        {true, asn1_class_context | asn1_tag_primitive, 2, "[2]", "82"},
        {true, asn1_class_context | asn1_tag_primitive, 15, "[15]", "8f"},
        {true, asn1_class_context | asn1_tag_primitive, 16, "[16]", "90"},
        {true, asn1_class_context | asn1_tag_primitive, 17, "[17]", "91"},
        {true, asn1_class_context | asn1_tag_primitive, 30, "[30]", "9e"},
        {true, asn1_class_context | asn1_tag_constructed, 0, "[0]", "a0"},
        {true, asn1_class_context | asn1_tag_constructed, 1, "[1]", "a1"},
        {true, asn1_class_context | asn1_tag_constructed, 15, "[15]", "af"},
        {true, asn1_class_context | asn1_tag_constructed, 30, "[30]", "be"},
        {true, asn1_class_application | asn1_tag_primitive, 0, "[APPLICATION 0]", "40"},
        {true, asn1_class_application | asn1_tag_primitive, 3, "[APPLICATION 3]", "43"},
        {true, asn1_class_application | asn1_tag_constructed, 3, "[APPLICATION 3]", "63"},
        {true, asn1_class_private | asn1_tag_primitive, 0, "[PRIVATE 0]", "c0"},
        {true, asn1_class_private | asn1_tag_primitive, 15, "[PRIVATE 15]", "cf"},
        // 8.1.2.4.3 he form of the identifier octets for a type with a tag whose number is greater than 30
        {true, asn1_class_universal | asn1_tag_primitive, 31, "DATE", "1f 1f"},                        // tag >= 31, 31
        {true, asn1_class_universal | asn1_tag_primitive, 32, "TIME-OF-DAY", "1f 20"},                 // tag >= 31, 32
        {true, asn1_class_universal | asn1_tag_primitive, 33, "DATE-TIME", "1f 21"},                   // tag >= 31, 33
        {true, asn1_class_universal | asn1_tag_primitive, 127, "[UNIVERSAL 127]", "1f 7f"},            // tag >= 31, 127
        {true, asn1_class_universal | asn1_tag_primitive, 128, "[UNIVERSAL 128]", "1f 81 00"},         // // tag >= 31, 128 = (1 * 128) + 0
        {true, asn1_class_universal | asn1_tag_primitive, 255, "[UNIVERSAL 255]", "1f 81 7f"},         // // tag >= 31, 255 = (1 * 128) + 127
        {true, asn1_class_universal | asn1_tag_primitive, 256, "[UNIVERSAL 256]", "1f 82 00"},         // // tag >= 31, 256 = (2 * 128) + 0
        {true, asn1_class_universal | asn1_tag_primitive, 16383, "[UNIVERSAL 16383]", "1f ff 7f"},     // tag >= 31, 16383 = (127 * 128) + 127
        {true, asn1_class_universal | asn1_tag_primitive, 16384, "[UNIVERSAL 16384]", "1f 81 80 00"},  // tag >= 31, 16384 = (1 * 128 * 128) + (0 * 128) + 0
        {true, asn1_class_context | asn1_tag_primitive, 31, "[31]", "9f 1f"},                          // tag >= 31, 31
        {true, asn1_class_context | asn1_tag_primitive, 32, "[32]", "9f 20"},                          // tag >= 31, 32
        {true, asn1_class_context | asn1_tag_primitive, 128, "[128]", "9f 81 00"},                     // tag >= 31, 128 = (1 * 128) + 0
        {true, asn1_class_application | asn1_tag_primitive, 31, "[APPLICATION 31]", "5f 1f"},          // tag >= 31, 31
        {true, asn1_class_application | asn1_tag_primitive, 128, "[APPLICATION 128]", "5f 81 00"},     // tag >= 31, 128 = (1 * 128) + 0
        {true, asn1_class_context | asn1_tag_constructed, 31, "[31]", "bf 1f"},
        {true, asn1_class_context | asn1_tag_constructed, 128, "[128]", "bf 81 00"},
        // negative/invalid test vector
        {false, asn1_class_universal | asn1_tag_primitive, 31, "[UNIVERSAL 31]", "1f"},           // high-tag form but no followings
        {false, asn1_class_universal | asn1_tag_primitive, 31, "[UNIVERSAL 31]", "1f 80"},        // continuation bit not terminated
        {false, asn1_class_universal | asn1_tag_primitive, 31, "[UNIVERSAL 31]", "1f 80 80 80"},  // continuation ...
        {false, asn1_class_universal | asn1_tag_primitive, 31, "[UNIVERSAL 31]", "1f 80 1f"},     // non-minimal encoding (denied if DER)
    };

    /**
    | class                  | tag                  |    | notation         |
    | --                     | --                   | -- | --               |
    | asn1_class_universal   | asn1_tag_primitive   | 31 | DATE             |
    | asn1_class_universal   | asn1_tag_constructed | 31 | ERROR            |
    | asn1_class_application | asn1_tag_primitive   | 31 | [APPLICATION 31] |
    | asn1_class_application | asn1_tag_constructed | 31 | [APPLICATION 31] |
    | asn1_class_context     | asn1_tag_primitive   | 31 | [31]             |
    | asn1_class_context     | asn1_tag_constructed | 31 | [31]             |
    | asn1_class_private     | asn1_tag_primitive   | 31 | [PRIVATE 31]     |
    | asn1_class_private     | asn1_tag_constructed | 31 | [PRIVATE 31]     |
    */

    auto lambda_builder = [](uint8 ident, uint64 tag) -> asn1_object* {
        if (asn1_class_universal == (ident & asn1_class_mask)) {
            auto obj = new asn1_builtin_type((asn1_entity_t)tag);
            if (ident & asn1_tag_constructed) {
                obj->as_constructed();
            }
            return obj;
        } else {
            return new asn1_tag(ident, tag);
        }
    };

    for (size_t i = 0; i < RTL_NUMBER_OF(table); ++i) {
        const auto& item = table[i];

        uint8 ident = 0;
        uint64 tag = 0;
        binary_t bin_expect = base16_decode_rfc(item.der);
        if (item.ispositive) {
            binary_t bin;

            // encode
            asn1_encode::asn1_ident_octets(bin, item.ident, item.tag);
            _test_case.assert(bin == bin_expect, __FUNCTION__, R"(encode DER %s expect "%s")", base16_encode(bin).c_str(), item.der);

            // publish
            {
                auto schema = lambda_builder(item.ident, item.tag);
                basic_stream bs_notation;
                binary_t bin_der;
                schema->publish(&bs_notation);
                schema->publish(&bin_der);

                _logger->write([&](basic_stream& bs) -> void {
                    valist va;
                    va << bs_notation << bin_der;
                    bs.vaprintln("notation {1:s}", va);
                    bs.vaprintln("DER      {2:x}", va);  // base16 encoding
                });
                _test_case.assert(bs_notation == item.notation, __FUNCTION__, "notation %s", item.notation);
                _test_case.assert(bin == bin_der, __FUNCTION__, R"(publish %s expect "%s")", base16_encode(bin_der).c_str(), item.der);
                schema->release();
            }

            // decode
            asn1_encode::read_asn1_ident_octets(bin.data(), bin.size(), ident, tag);
            _test_case.assert((ident == item.ident) && (tag == item.tag), __FUNCTION__, "read identifier %02x tag %I64u", ident, tag);
        } else {
            // invalid test vector (check bad_data)
            auto ret = asn1_encode::read_asn1_ident_octets(bin_expect.data(), bin_expect.size(), ident, tag);
            _test_case.assert(ret == errorcode_t::bad_data, __FUNCTION__, "invalid test vector %s", item.der);
        }
    }
}

// X.690 8.1.3 Length octets
void test_x690_8_1_3_length_octets() {
    _test_case.begin("ITU-T X.690 8.1.3");
    struct testvector {
        uint64 i;
        const char* expect;
    } _table[] = {
        // short form
        {0, "00"},
        {1, "01"},
        {2, "02"},
        {10, "0a"},
        {16, "10"},
        {32, "20"},
        {38, "26"},
        {50, "32"},
        {64, "40"},
        {100, "64"},
        {126, "7e"},
        {127, "7f"},
        // long form
        {128, "81 80"},
        {129, "81 81"},
        {200, "81 c8"},
        {201, "81 c9"},
        {255, "81 ff"},
        {256, "82 01 00"},
        {257, "82 01 01"},
        {300, "82 01 2c"},
        {512, "82 02 00"},
        {1024, "82 04 00"},
        {4096, "82 10 00"},
        {65535, "82 ff ff"},
        {65536, "83 01 00 00"},
        {16777215, "83 ff ff ff"},
        {16777216, "84 01 00 00 00"},
        {2147483647, "84 7f ff ff ff"},
        {4294967295, "84 ff ff ff ff"},
        {4294967296ULL, "85 01 00 00 00 00"},
        {18446744073709551615ULL, "88 ff ff ff ff ff ff ff ff"},
        // BER Indefinite Length
        // Empty Constructed Object
        // 30 80 00 00
        // SEQUENCE Length = indefinite EOC
        // Nested
        // 30 80
        //    30 80
        //       02 01 01
        //    00 00
        // 00 00
    };
    // DER invalid cases
    // 127 "81 7f"
    // 1   "81 01"
    // 0   "81 00"
    // 128 "82 00 80"
    // 256 "83 00 01 00"
    // "81" long form, no length octet
    // "82 01"    2 bytes required, 1 byte exist
    // "83 01 00" 3 ...
    // "ff"       X.690 reserved

    for (auto entry : _table) {
        binary_t bin;
        asn1_encode::t_asn1_length_octets<uint64>(bin, entry.i);

        {
            test_case_notimecheck notimecheck(_test_case);

            _logger->writeln("%I64u -> %s", entry.i, base16_encode(bin).c_str());
            bool test = (bin == base16_decode_rfc(entry.expect));
            _test_case.assert(test, __FUNCTION__, "X.690 8.1.3 length octets [%I64u] expect [%s]", entry.i, entry.expect);
        }
    }
}

// X.690 8.1.5 end-of-contents octets
void test_x690_8_1_5_end_of_contents() {
    _test_case.begin("ITU-T X.690");
    asn1_encode enc;
    binary_t bin;
    enc.end_contents(bin);
    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln("end of contents -> %s", base16_encode(bin).c_str());
        _test_case.assert(bin == base16_decode("0000"), __FUNCTION__, "X.690 8.1.5 end-of-contents octets");
    }
}

void test_x690_encoding_value() {
    _test_case.begin("ITU-T X.690 8.2, 8.3, 8.5, 8.8");
    struct testvector {
        asn1_entity_t entity;
        variant var;
        const char* expect;
        const char* text;
        int debug;
    } _table[] = {
        {asn1_entity_null, variant(), "05 00", "X.690 8.8"},
        {asn1_entity_boolean, variant(true), "0101ff", "X.690 8.2"},
        {asn1_entity_boolean, variant(false), "010100", "X.690 8.2"},

        // using pyasn1
        // >>> from pyasn1.type import univ
        // >>> from pyasn1.codec.der.encoder import encode
        // >>> from pyasn1.codec.der.decoder import decode
        // >>> import binascii
        // >>>
        // >>> encode(univ.Integer(-128)).hex()
        // >>> print("Decoded Integer:", decode(binascii.unhexlify('020180'), asn1Spec=univ.Integer()))
        // >>>
        // >>> encode(univ.Real(0.0)).hex()
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090380fb05'), asn1Spec=univ.Real()))

        // X.690 10.1 Length forms
        // The definite form of length encoding shall be used, encoded in the minimum number of octets. [Contrast with 8.1.3.2 b).]
        //
        // 1. signed int8 [0xff..0x7f]
        //   1) negative [0x80..0xff]
        //     -128(0x80), -127(0x81), ..., -1(0xff)
        //     T 02
        //     L 01
        //     V 80..ff
        //   2) positive [0x00..0x7f]
        //     0(0x00), ..., 127(0x7f)
        //     T 02
        //     L 01
        //     V 00..7f
        //   3) encoding for -128
        //     >>> print("Decoded Integer:", decode(binascii.unhexlify('020180'), asn1Spec=univ.Integer()))
        //     Decoded Integer: (<Integer value object, tagSet <TagSet object, tags 0:0:2>, payload [-128]>, b'')
        //     >>> encode(univ.Integer(-128)).hex()
        //     '0202ff80'
        // 2. signed int18 [0xffff..0x7fff]
        //   1) negative [0x8000..0xffff]
        //     -32768(0x8000), -32767(0x8001), ..., -1(0xffff)
        //     T 02
        //     L 02
        //     V 8000..ffff
        //   2) positive [0x0000..0x7fff]
        //     0(0x0000), ..., 32767(0x7fff)
        //     T 02
        //     L 02
        //     V 0000..7ffff
        //   3) encoding for -32768
        //     >>> print("Decoded Integer:", decode(binascii.unhexlify('02028000'), asn1Spec=univ.Integer()))
        //     Decoded Integer: (<Integer value object, tagSet <TagSet object, tags 0:0:2>, payload [-32768]>, b'')
        //     >>> encode(univ.Integer(-32768)).hex()
        //     '0203ff8000'
        // 3. and more cases
        //     >>> print("Decoded Integer:", decode(binascii.unhexlify('0203800000'), asn1Spec=univ.Integer()))
        //     Decoded Integer: (<Integer value object, tagSet <TagSet object, tags 0:0:2>, payload [-8388608]>, b'')
        //     >>> print("Decoded Integer:", decode(binascii.unhexlify('020480000000'), asn1Spec=univ.Integer()))
        //     Decoded Integer: (<Integer value object, tagSet <TagSet object, tags 0:0:2>, payload [-2147483648]>, b'')

        {asn1_entity_integer, variant(0), "02 01 00", "x.690 8.3"},
        {asn1_entity_integer, variant(123), "02 01 7b", "x.690 8.3"},
        {asn1_entity_integer, variant(127), "02 01 7f", "x.690 8.3"},
        {asn1_entity_integer, variant(128), "02 02 00 80", "x.690 8.3"},
        {asn1_entity_integer, variant(129), "02 02 00 81", "x.690 8.3"},
        {asn1_entity_integer, variant(255), "02 02 00 ff", "x.690 8.3"},
        {asn1_entity_integer, variant(256), "02 02 01 00", "x.690 8.3"},
        {asn1_entity_integer, variant(257), "02 02 01 01", "x.690 8.3"},
        {asn1_entity_integer, variant(300), "02 02 01 2c", "x.690 8.3"},
        {asn1_entity_integer, variant(1000), "02 02 03 e8", "x.690 8.3"},
        {asn1_entity_integer, variant(32767), "02 02 7f ff", "x.690 8.3"},
        {asn1_entity_integer, variant(32768), "02 03 00 80 00", "x.690 8.3"},
        {asn1_entity_integer, variant(32769), "02 03 00 80 01", "x.690 8.3"},
        {asn1_entity_integer, variant(65534), "02 03 00 ff fe", "x.690 8.3"},
        {asn1_entity_integer, variant(65535), "02 03 00 ff ff", "x.690 8.3"},
        {asn1_entity_integer, variant(65536), "02 03 01 00 00", "x.690 8.3"},
        {asn1_entity_integer, variant(65537), "02 03 01 00 01", "x.690 8.3"},
        {asn1_entity_integer, variant(16777215), "02 04 00 ff ff ff", "x.690 8.3"},
        {asn1_entity_integer, variant(123456789), "02 04 07 5B CD 15", "x.690 8.3"},
        {asn1_entity_integer, variant(2147483647), "02 04 7f ff ff ff", "x.690 8.3"},
#ifdef __SIZEOF_INT128__
        {asn1_entity_integer, variant(4294967295), "020500ffffffff", "x.690 8.3"},
        {asn1_entity_integer, variant(4294967296), "02 05 01 00 00 00 00", "x.690 8.3"},
        {asn1_entity_integer, variant(1099511627775), "02 06 00 ff ff ff ff ff", "x.690 8.3"},
        {asn1_entity_integer, variant(1152921504606846975), "02080fffffffffffffff", "x.690 8.3", 1},
        {asn1_entity_integer, variant(1152921504606846976), "02081000000000000000", "x.690 8.3", 1},
#endif
        {asn1_entity_integer, variant(-1), "02 01 ff", "x.690 8.3"},
        {asn1_entity_integer, variant(-10), "02 01 f6", "x.690 8.3"},
        {asn1_entity_integer, variant(-126), "02 01 82", "x.690 8.3"},
        {asn1_entity_integer, variant(-127), "02 01 81", "x.690 8.3"},
        {asn1_entity_integer, variant(-128), "02 01 80", "x.690 8.3"},
        {asn1_entity_integer, variant(-129), "02 02 ff 7f", "x.690 8.3"},
        {asn1_entity_integer, variant(-136), "02 02 ff 78", "x.690 8.3"},
        {asn1_entity_integer, variant(-256), "02 02 ff 00", "x.690 8.3"},
        {asn1_entity_integer, variant(-257), "02 02 fe ff", "x.690 8.3"},
        {asn1_entity_integer, variant(-300), "02 02 fe d4", "x.690 8.3"},
        {asn1_entity_integer, variant(-1234), "02 02 fb 2e", "x.690 8.3"},
        {asn1_entity_integer, variant(-32768), "02 02 80 00", "x.690 8.3"},
        {asn1_entity_integer, variant(-32769), "02 03 ff 7f ff", "x.690 8.3"},
        {asn1_entity_integer, variant(-8388607), "02 03 80 00 01", "x.690 8.3"},
        {asn1_entity_integer, variant(-16777216), "02 04 ff 00 00 00", "x.690 8.3"},
        {asn1_entity_integer, variant(-16777217), "02 04 fe ff ff ff", "x.690 8.3"},
        {asn1_entity_integer, variant(-4294967296), "02 05 ff 00 00 00 00", "x.690 8.3"},
        {asn1_entity_integer, variant(-1099511627775), "02 06 ff 00 00 00 00 01", "x.690 8.3"},
        {asn1_entity_integer, variant(-1099511627776), "02 06 ff 00 00 00 00 00", "x.690 8.3"},

        {asn1_entity_real, variant(0.0f), "0900", "X.690 8.5"},
        // e -20 m 129453.0
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090580ec01f9ad'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [0.12345600128173828]>, b'')
        {asn1_entity_real, variant(0.123456f), "090580ec01f9ad", "X.690 8.5"},
        // 2^-3 + 2^-5 -> 0.00101 -> 1.01 * 2^-3 (IEEE754) -> 101 * 2^-5
        {asn1_entity_real, variant(0.15625), "090380fb05", "X.690 8.5"},
        // 2^-1 (IEEE754) -> 0.1 -> 1.0 * 2^-1 (IEEE754)
        // >>> encode(univ.Real(0.5)).hex()
        // '09050335452d31'
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090380FF01'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [0.5]>, b'')
        {asn1_entity_real, variant(0.5), "090380FF01", "X.690 8.5"},
        // 2^-1 + 2^-2 -> 0.11 -> 1.1 * 2^-1 (IEEE754) -> 11 * 2^-2 (ASN.1)
        {asn1_entity_real, variant(0.75), "090380fe03", "X.690 8.5"},
        // 1.0 * 2^0 (IEEE754) -> 80 00 01
        {asn1_entity_real, variant(1.0), "0903800001", "X.690 8.5"},
        // e -21 m 2579497.0
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090580EB275C29'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [1.2300000190734863]>, b'')
        {asn1_entity_real, variant(1.23f), "090580EB275C29", "X.690 8.5"},
        // 2^1 -> 10 -> 1.0 * 2^1 (IEEE754) -> 80 01 01
        {asn1_entity_real, variant(2.0), "0903800101", "X.690 8.5"},
        // 2^5 + 2^-2 + 2^2-4 -> 100000.0101 -> 1.000000101 * 2^5 (IEEE754) -> 1000000101 * 2^-4
        {asn1_entity_real, variant(32.3125), "090480fc0205", "X.690 8.5"},
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090680ef009dcccd'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [78.9000015258789]>, b'')
        {asn1_entity_real, variant(78.90f), "090680ef009dcccd", "X.690 8.5"},
        {asn1_entity_real, variant(123.0), "090380007b", "X.690 8.5"},
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090680ef00f6e979'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [123.45600128173828]>, b'')
        {asn1_entity_real, variant(123.456f), "090680ef00f6e979", "X.690 8.5"},
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090680f600c0e6b7'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [12345.6787109375]>, b'')
        {asn1_entity_real, variant(12345.6789f), "090680f600c0e6b7", "X.690 8.5"},
        // (-1)^1 * 1.0 * 2^0 (IEEE754) -> c0 00 01
        {asn1_entity_real, variant(-1.0), "0903c00001", "X.690 8.5"},
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('0905c0eb275c29'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [-1.2300000190734863]>, b'')
        {asn1_entity_real, variant(-1.23f), "0905c0eb275c29", "X.690 8.5"},
        {asn1_entity_real, variant(-456.0), "0903c00339", "X.690 8.5"},
        {asn1_entity_real, variant(fp32_from_binary32(fp32_pinf)), "090140", "X.690 8.5 Inf"},
        {asn1_entity_real, variant(fp32_from_binary32(fp32_ninf)), "090141", "X.690 8.5 -Inf"},
        {asn1_entity_real, variant(fp32_from_binary32(fp32_nan)), "090142", "X.690 8.5 NaN"},
        {asn1_entity_real, variant(-0.0f), "090143", "X.690 8.5 -0.0"},
        {asn1_entity_real, variant(fp64_from_binary64(fp64_pinf)), "090140", "X.690 8.5 Inf"},
        {asn1_entity_real, variant(fp64_from_binary64(fp64_ninf)), "090141", "X.690 8.5 -Inf"},
        {asn1_entity_real, variant(fp64_from_binary64(fp64_nan)), "090142", "X.690 8.5 NaN"},
        {asn1_entity_real, variant(-0.0), "090143", "X.690 8.5 -0.0"},
    };

    _test_case.reset_time();

    asn1_encode enc;

    for (auto entry : _table) {
        binary_t bin_expect = base16_decode_rfc(entry.expect);

        // encoding routine
        {
            binary_t bin;
            enc.encode(bin, entry.entity, entry.var);

            test_case_notimecheck notimecheck(_test_case);

            _logger->writeln("%s", base16_encode(bin).c_str());

            return_t ret = errorcode_t::success;
            if (bin_expect.empty()) {
                ret = errorcode_t::not_supported;
            } else if (bin != bin_expect) {
                ret = errorcode_t::mismatch;
            }

            basic_stream bs;
            vtprintf(&bs, entry.var);
            _test_case.test(ret, __FUNCTION__, "%s [%s] expect [%s]", entry.text, bs.c_str(), entry.expect);
            bin.clear();
        }

        // asn1_builtin_type
        auto builtin = new asn1_builtin_type(entry.entity);
        {
            auto value = builtin->instantiate();
            binary_t bin;
            basic_stream bs;

            value->set(entry.var);

            builtin->publish(&bs);
            value->publish(&bin);

            _logger->write([&](basic_stream& dbs) -> void {
                valist va;
                va << bs << bin;
                dbs.vaprintln("notation {1}", va);
                dbs.vaprintln("DER      {2:x}", va);
            });

            _test_case.assert(bin_expect == bin, __FUNCTION__, "%s [%s] expect [%s]", entry.text, bs.c_str(), entry.expect);

            value->release();
            builtin->release();
        }
    }
}

void do_dump_asn1(asn1_value* object, const char* expect, const char* text) {
    if (object && expect && text) {
        basic_stream bs;
        binary_t bin;
        object->publish(&bs);
        object->publish(&bin);
        _logger->write([&](basic_stream& dbs) -> void {
            valist va;
            va << bs << bin;
            dbs.vaprintln("notation {1:s}", va);
            dbs.vaprintln("DER      {2:x}", va);
        });

        _test_case.assert(bin == base16_decode_rfc(expect), __FUNCTION__, "%s [%s]", text, expect);
    }
}

void test_x690_encoding_typevalue() {
    _test_case.begin("ITU-T X.690 type and value");

    // X.690 8.14 encoding of a value of a prefixed type
    // case 1. Type1 ::= VisibleString
    auto type1 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
    // case 2. Type2 ::= [Application 3] implicit Type1
    auto type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, type1->clone()));
    // case 3. Type3 ::= [2] Type2
    auto type3 = asn1_referenced_type::define("Type3", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, type2->clone()));
    // case 4. Type4 ::= [Application 7] implicit Type3
    auto type4 = asn1_referenced_type::define("Type4", new asn1_tagged_type(asn1_class_application, 7, asn1_implicit, type3->clone()));
    // case 5. Type5 ::= [2] implicit Type2
    auto type5 = asn1_referenced_type::define("Type5", new asn1_tagged_type(asn1_class_context, 2, asn1_implicit, type2->clone()));

    struct testvector {
        asn1_object* obj;
        variant var;
        const char* expect;
        const char* text;
    } _table[] = {
        // X.690 8.2
        {new asn1_builtin_type(asn1_entity_boolean), variant(true), "01 01 ff", "X.690 8.2 true"},

        // X.690 8.3
        {new asn1_builtin_type(asn1_entity_integer), variant(128), "02 02 00 80", "X.690 8.3 128"},
        {new asn1_builtin_type(asn1_entity_integer), variant(300), "02 02 01 2c", "X.690 8.3 300"},
        {new asn1_builtin_type(asn1_entity_integer), variant(-127), "02 01 81", "X.690 8.3 -127"},

        // X.690 8.5
        {new asn1_builtin_type(asn1_entity_real), variant(1.0), "0903800001", "X.690 8.5 1.0"},
        {new asn1_builtin_type(asn1_entity_real), variant(-1.0), "0903c00001", "X.690 8.5 -1.0"},

        // X.690 8.6 encoding of a bitstring value
        // commencing with the leading bit and proceeding to the trailing bit
        // if(size(input) % 2) { pad = '0'; padbit = 4; }
        // encode(asn1_tag_bitstring).encode(padbit).encode(input).encode(pad)
        {new asn1_builtin_type(asn1_entity_bitstring), variant("0a3b5f291cd"), "03 07 04 0A 3B 5F 29 1C D0", "X.690 8.6.4.2 0a3b5f291cd"},

        // X.690 8.7
        {new asn1_builtin_type(asn1_entity_octstring), variant("0123456789abcdef"), "04 08 01 23 45 67 89 ab cd ef", "X.690 8.7.4 0123456789abcdef"},

        // X.690 8.8
        {new asn1_builtin_type(asn1_entity_null), variant(), "05 00", "X.690 8.8 null"},

        // X.690 8.9
        {new asn1_builtin_type(asn1_entity_ia5string), variant("Smith"), "16 05 53 6d 69 74 68", "X.690 8.9 Smith"},
        {new asn1_builtin_type(asn1_entity_ia5string), variant("test1@rsa.com"), "16 0d 74 65 73 74 31 40 72 73 61 2e 63 6f 6d", "X.690 8.9 test1@rsa.com"},

        // X.690 11.7 generalized time
        {new asn1_builtin_type(asn1_entity_generalizedtime), variant(datetime_t(1992, 5, 21, 0, 0, 0)), "18 0F 31 39 39 32 30 35 32 31 30 30 30 30 30 30 5A",
         "X.690 11.7 #1"},  // 19920521000000Z
        {new asn1_builtin_type(asn1_entity_generalizedtime), variant(datetime_t(1992, 6, 22, 12, 34, 21)), "18 0F 31 39 39 32 30 36 32 32 31 32 33 34 32 31 5A",
         "X.690 11.7 #2"},  // 19920622123421Z
        {new asn1_builtin_type(asn1_entity_generalizedtime), variant(datetime_t(1992, 7, 22, 13, 21, 00, 3)), "18 11 31 39 39 32 30 37 32 32 31 33 32 31 30 30 2E 33 5A",
         "X.690 11.7 #3"},  // 19920722132100.3Z

        // X.690 8.14 encoding of a tagged value
        // case 1. Type1 ::= VisibleString
        {type1, variant("Jones"), "1A 05 4A 6F 6E 65 73", "X.690 8.14 Type1"},
        // case 2. Type2 ::= [Application 3] implicit Type1
        {type2, variant("Jones"), "43 05 4A 6F 6E 65 73", "X.690 8.14 Type2"},
        // case 3. Type3 ::= [2] Type2
        {type3, variant("Jones"), "a2 07 43 05 4A 6F 6E 65 73", "X.690 8.14 Type3"},
        // case 4. Type4 ::= [Application 7] implicit Type3
        {type4, variant("Jones"), "67 07 43 05 4A 6F 6E 65 73", "X.690 8.14 Type4"},
        // case 5. Type5 ::= [2] implicit Type2
        {type5, variant("Jones"), "82 05 4A 6F 6E 65 73", "X.690 8.14 Type5"},

        // X.690 8.19 object identifier
        // http://oid-info.com/cgi-bin/display?tree=
        // ITU-T(0)
        // ISO(1)
        // - member-body(2)
        //   - us(840)
        // - identified-organizaton(3)
        //   - dod(6)
        //     - internet(1)
        //       - private(4)
        //         - enterprise(1)
        // joint-iso-itu-t(2)
        {new asn1_builtin_type(asn1_entity_objid), variant("1.3.6.1.4.1"), "06 05 2b 06 01 04 01", "X.690 8.19 OID #1"},
        {new asn1_builtin_type(asn1_entity_objid), variant("1.2.840.113549"), "06 06 2A 86 48 86 F7 0d", "X.690 8.19 OID #2"},
        {new asn1_builtin_type(asn1_entity_objid), variant("1.3.6.1.4.1.311.21.20"), "06 09 2b 06 01 04 01 82 37 15 14", "X.690 8.19 OID #3"},
        {new asn1_builtin_type(asn1_entity_objid), variant("1.3.6.1.4.1.311.60.2.1.1"), "06 0B 2B 06 01 04 01 82 37 3C 02 01 01", "X.690 8.19 OID #4"},
        {new asn1_builtin_type(asn1_entity_objid), variant("1.2.840.10045.3.1.7"), "06 08 2a 86 48 ce 3d 03 01 07", "X.690 8.19 #5"},
        {new asn1_builtin_type(asn1_entity_objid), variant("2.100.3"), "06 03 81 34 03", "X.690 8.19 OID #6"},  // 0..39 < 100 ??
        {new asn1_builtin_type(asn1_entity_objid), variant("2.154"), "06 02 81 6a", "X.690 8.19 OID #7"},

        // X.690 8.20 encoding of a relative object identifier value
        {new asn1_builtin_type(asn1_entity_reloid), variant("8571.3.2"), "0D 04 C27B0302", "X.690 8.20 relative object identifier"},

        // X.690 8.21.5.4 Example Name ::= VisibleString
        {new asn1_builtin_type(asn1_entity_visiblestring), variant("Jones"), "1a 05 4a6f6e6573", "X.690 8.21 VisibleString"},
        // X.690 8.23
        {new asn1_builtin_type(asn1_entity_printstring), variant("Test User 1"), "13 0b 54 65 73 74 20 55 73 65 72 20 31", "X.690 8.23 PrintableString"},
        {new asn1_builtin_type(asn1_entity_t61string), variant("cl'es publiques"), "14 0f 63 6c 27 65 73 20 70 75 62 6c 69 71 75 65 73",
         "X.690 8.23 T61String"},  // // replace Â C2 for ' 27
    };

    for (auto item : _table) {
        auto inst = item.obj->instantiate();
        inst->set(item.var);

        do_dump_asn1(inst, item.expect, item.text);

        inst->release();
        item.obj->release();
    }
}

void test_x690_constructed() {
    _test_case.begin("ITU-T X.690 constructed");

    // constructed
    // X.690 10.2 String encoding forms
    // For bitstring, octetstring and restricted character string types, the constructed form of encoding shall not be used. (Contrast with 8.23.6.)
    {
        binary_t bin;
        bin << uint8(asn1_tag_bitstring | asn1_tag_constructed) << uint8(0x80) << uint8(asn1_tag_bitstring);
        asn1_encode::t_asn1_length_octets<uint32>(bin, 3);
        bin << base16_decode("000a3b") << uint8(asn1_tag_bitstring);
        asn1_encode::t_asn1_length_octets<uint32>(bin, 5);
        bin << base16_decode("045f291cd0") << uint8(0x00)  // EOC
            << uint8(0x00);                                // EOC
        _logger->writeln("%s", base16_encode(bin).c_str());
        const char* expect_constructed = "23 80 03 03 00 0A 3B 03 05 04 5F 29 1C D0 00 00";
        _test_case.assert(bin == base16_decode_rfc(expect_constructed), __FUNCTION__, "X.690 8.6.4 BitString constructed");
    }
}

// X.690 8.9 encoding of a sequence value
void test_x690_8_9_sequence() {
    _test_case.begin("ITU-T X.690 8.9");
    // Sequence Length  Contents
    // 30_16    0A_16
    //                  IA5String  Length  Contents
    //                  16_16      05_16   "Smith"
    //                  Boolean    Length  Contents
    //                  01_16      01_16   FF_16

    asn1 notation;
    asn1_encode enc;

    constexpr char type[] = R"(SEQUENCE {name IA5String, ok BOOLEAN})";
    constexpr char val[] = R"(SEQUENCE {name "Smith", ok TRUE})";
    constexpr char expect[] = "30 0A 16 05 53 6D 69 74 68 01 01 FF";
    binary_t bin_expect = base16_decode_rfc(expect);

    auto seq = new asn1_sequence;
    *seq << new asn1_builtin_type("name", asn1_entity_ia5string) << new asn1_builtin_type("ok", asn1_entity_boolean);
    notation << seq;
    auto value = seq->instantiate();
    (*value).set("name", "Smith").set("ok", true);

    binary_t bin;
    basic_stream bs_type;
    basic_stream bs_value;

    seq->publish(&bs_type);
    value->publish(&bs_value);
    value->publish(&bin);
    _logger->write([&](basic_stream& dbs) -> void {
        valist va;
        va << bs_type << bs_value << bin;
        dbs.vaprintln("type  {1}", va);
        dbs.vaprintln("value {2}", va);
        dbs.vaprintln("DER   {3:x}", va);
    });

    _test_case.assert(bs_type == type, __FUNCTION__, "type %s", type);
    _test_case.assert(bs_value == val, __FUNCTION__, "value %s", val);
    _test_case.assert(bin_expect == bin, __FUNCTION__, "expect %s", expect);
}

void test_testvector_chatgpt() {
    _test_case.begin("testvector GPT");

    // Test 1 Length aggregation
    // Test 2. IMPLICIT Replace
    // Test 3. EXPLICIT Wrap
    // Test 4. IMPLICIT + EXPLICIT Chain
    // Test 5. Primitive / Constructed Bit propagation
    // Test 6. Constructed Type propagation
    // Test 7. Nested Length
    // Test 8. DER SET Ordering
    {
        auto case1_type1 = new asn1_sequence({new asn1_builtin_type("name", asn1_entity_visiblestring), new asn1_builtin_type("ok", asn1_entity_boolean)});
        auto case1_type2 = new asn1_sequence({{"name", asn1_entity_visiblestring}, {"ok", asn1_entity_boolean}});

        auto case2_type1 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
        auto case2_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, case2_type1->clone()));

        auto case3_type1 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
        auto case3_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, case3_type1->clone()));

        auto case4_type1 = asn1_referenced_type::define("Type1", asn1_entity_visiblestring);
        auto case4_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, case4_type1->clone()));
        auto case4_type3 = asn1_referenced_type::define("Type3", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit, case4_type2->clone()));
        auto case4_type4 = asn1_referenced_type::define("Type4", new asn1_tagged_type(asn1_class_application, 7, asn1_implicit, case4_type3->clone()));
        auto case4_type5 = asn1_referenced_type::define("Type5", new asn1_tagged_type(asn1_class_context, 2, asn1_implicit, case4_type2->clone()));

        auto case5_type1 = asn1_referenced_type::define("Type1", asn1_entity_real);
        auto case5_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, case5_type1->clone()));

        auto case6_type1 = asn1_referenced_type::define("Type1", new asn1_sequence({new asn1_builtin_type("name", asn1_entity_visiblestring)}));
        auto case6_type2 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, case6_type1->clone()));
        auto case6_type3 = asn1_referenced_type::define("Type1", new asn1_sequence({{"name", asn1_entity_visiblestring}}));
        auto case6_type4 = asn1_referenced_type::define("Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, case6_type3->clone()));

        auto case7_outer =
            asn1_referenced_type::define("Outer", new asn1_sequence({new asn1_sequence("Inner", {new asn1_builtin_type("name", asn1_entity_visiblestring)})}));

        auto case8_type1 = new asn1_set({new asn1_builtin_type("a", asn1_entity_integer), new asn1_builtin_type("b", asn1_entity_boolean)});
        auto case8_type2 = new asn1_set({{"a", asn1_entity_integer}, {"b", asn1_entity_boolean}});

        struct testvector {
            asn1_object* obj;
            const char* name;
            variant vt;
            const char* notation;
            const char* der;
        } table[] = {
            {case1_type1, "Test 1 Length aggregation", 0, "SEQUENCE {name VisibleString, ok BOOLEAN}", "30 0A 1A 05 4A 6F 6E 65 73 01 01 FF"},
            {case1_type2, "Test 1 Length aggregation", 0, "SEQUENCE {name VisibleString, ok BOOLEAN}", "30 0A 1A 05 4A 6F 6E 65 73 01 01 FF"},

            {case2_type1, "Test 2. IMPLICIT Replace", "Jones", "Type1 ::= VisibleString", "1A 05 4A 6F 6E 65 73"},
            {case2_type2, "Test 2. IMPLICIT Replace", "Jones", "Type2 ::= [APPLICATION 3] IMPLICIT Type1", "43 05 4A 6F 6E 65 73"},

            {case3_type1, "Test 3. EXPLICIT Wrap", "Jones", "Type1 ::= VisibleString", "1A 05 4A 6F 6E 65 73"},
            {case3_type2, "Test 3. EXPLICIT Wrap", "Jones", "Type2 ::= [2] EXPLICIT Type1", "A2 07 1A 05 4A 6F 6E 65 73"},

            {case4_type1, "Test 4. IMPLICIT + EXPLICIT Chain", "Jones", "Type1 ::= VisibleString", "1A 05 4A 6F 6E 65 73"},
            {case4_type2, "Test 4. IMPLICIT + EXPLICIT Chain", "Jones", "Type2 ::= [APPLICATION 3] IMPLICIT Type1", "43 05 4A 6F 6E 65 73"},
            {case4_type3, "Test 4. IMPLICIT + EXPLICIT Chain", "Jones", "Type3 ::= [2] EXPLICIT Type2", "A2 07 43 05 4A 6F 6E 65 73"},
            {case4_type4, "Test 4. IMPLICIT + EXPLICIT Chain", "Jones", "Type4 ::= [APPLICATION 7] IMPLICIT Type3", "67 07 43 05 4A 6F 6E 65 73"},
            {case4_type5, "Test 4. IMPLICIT + EXPLICIT Chain", "Jones", "Type5 ::= [2] IMPLICIT Type2", "82 05 4A 6F 6E 65 73"},

            {case5_type1, "Test 5. Primitive / Constructed Bit propagation", 1.0, "Type1 ::= REAL", "09 03 80 00 01"},
            {case5_type2, "Test 5. Primitive / Constructed Bit propagation", 1.0, "Type2 ::= [APPLICATION 3] IMPLICIT Type1", "43 03 80 00 01"},

            {case6_type1, "Test 6. Constructed Type propagation", 0, "Type1 ::= SEQUENCE {name VisibleString}", "30 07 1A 05 4A 6F 6E 65 73"},
            {case6_type2, "Test 6. Constructed Type propagation", 0, "Type2 ::= [APPLICATION 3] IMPLICIT Type1", "63 07 1A 05 4A 6F 6E 65 73"},
            {case6_type3, "Test 6. Constructed Type propagation", 0, "Type1 ::= SEQUENCE {name VisibleString}", "30 07 1A 05 4A 6F 6E 65 73"},
            {case6_type4, "Test 6. Constructed Type propagation", 0, "Type2 ::= [APPLICATION 3] IMPLICIT Type1", "63 07 1A 05 4A 6F 6E 65 73"},

            {case7_outer, "Test 7. Nested Length", 0, "Outer ::= SEQUENCE {Inner SEQUENCE {name VisibleString}}", "30 09 30 07 1A 05 4A 6F 6E 65 73"},

            {case8_type1, "Test 8. DER SET Ordering", 0, "SET {a INTEGER, b BOOLEAN}", "31 06 01 01 FF 02 01 05"},
            {case8_type2, "Test 8. DER SET Ordering", 0, "SET {a INTEGER, b BOOLEAN}", "31 06 01 01 FF 02 01 05"},
        };
        for (const auto& item : table) {
            basic_stream bs;
            binary_t bin;
            auto value = item.obj->instantiate();
            (*value).set(item.vt).set("name", "Jones").set("ok", true).set("a", 5).set("b", true);

            item.obj->publish(&bs);
            value->publish(&bin);

            _logger->write([&](basic_stream& dbs) -> void {
                valist va;
                va << bs << bin;
                dbs.vaprintln("type {1}", va);
                dbs.vaprintln("DER  {2:x}", va);
            });

            _test_case.assert(bs == item.notation, __FUNCTION__, "%s : %s", item.name, item.notation);
            _test_case.assert(bin == base16_decode_rfc(item.der), __FUNCTION__, "%s : %s", item.name, item.der);

            value->release();
            item.obj->release();
        }
    }
}

void test_x690_time() {
    _test_case.begin("ITU-T X.690 UTCTime");
    datetime_t dt(1991, 5, 6, 16, 45, 40);
    binary_t bin;
    asn1_encode enc;
    enc.utctime(bin, dt, -420);
    _logger->writeln("%s", base16_encode(bin).c_str());
    _test_case.assert(bin == base16_decode_rfc("17 0d 39 31 30 35 30 36 32 33 34 35 34 30 5a"), __FUNCTION__, "X.690 UTCTime");
}

void test_asn1_object() {
    _test_case.begin("ASN.1 object");
    // $pattern_builtintype
    //     new asn1_builtin_type(builtintype)
    // [$pattern_class 1] $pattern_taggedmode $pattern_builtintype
    //     new asn1_builtin_type(builtintype, new asn1_tag(asn1_class_application, 3, asn1_implicit)));
    // lvalue ::= $pattern_builtintype
    //     new asn1_builtin_type(lvalue, builtintype, new asn1_tag(asn1_class_application, 3, asn1_implicit)));
    // name $pattern_builtintype
    //     new asn1_builtin_type(name, new asn1_builtin_type(builtintype, new asn1_tag(asn1_class_application, 3, asn1_implicit))));
    struct testvector2 {
        const char* note;
        asn1_object* asn1obj;
    };
    testvector2 table2[] = {
        {"BOOLEAN", new asn1_builtin_type(asn1_entity_boolean)},
        {"INTEGER", new asn1_builtin_type(asn1_entity_integer)},
        {"OCTET STRING", new asn1_builtin_type(asn1_entity_octstring)},
        {"NULL", new asn1_builtin_type(asn1_entity_null)},
        {"OBJECT IDENTIFIER", new asn1_builtin_type(asn1_entity_objid)},
        {"REAL", new asn1_builtin_type(asn1_entity_real)},
        {"SEQUENCE {name IA5String, ok BOOLEAN}",
         new asn1_sequence({new asn1_builtin_type("name", asn1_entity_ia5string), new asn1_builtin_type("ok", asn1_entity_boolean)})},
        {"Date ::= VisibleString", asn1_referenced_type::define("Date", asn1_entity_visiblestring)},
        {"Date ::= [APPLICATION 3] IMPLICIT VisibleString",
         asn1_referenced_type::define("Date", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit, asn1_entity_visiblestring))},
        {"Date ::= [0] IMPLICIT VisibleString",
         asn1_referenced_type::define("Date", new asn1_tagged_type(asn1_class_context, 0, asn1_implicit, asn1_entity_visiblestring))},
        {"Date ::= [PRIVATE 0] IMPLICIT VisibleString",
         asn1_referenced_type::define("Date", new asn1_tagged_type(asn1_class_private, 0, asn1_implicit, asn1_entity_visiblestring))},
    };

    basic_stream bs;
    asn1* object = new asn1;
    for (auto item : table2) {
        *object << item.asn1obj;
        object->publish(&bs);
        object->clear();
        _logger->writeln(bs);
        _test_case.assert(bs == item.note, __FUNCTION__, "publish %s", item.note);

        // compare
        parser p;
        parser::context ctx;
        parser::search_result res;
        p.parse(ctx, item.note);
        res = p.wsearch(ctx, bs);
        bs.clear();

        auto result = p.psearchex(ctx);
        auto dump_handler = [&](const token_description* desc) -> void {
            _logger->writeln("> type %d(%s) tag %i index %d pos %zi len %zi (%.*s)", desc->type, p.typeof_token(desc->type).c_str(), desc->tag, desc->index, desc->pos,
                             desc->size, (unsigned)desc->size, desc->p);
        };
        std::map<uint32, asn1_entity_t> typemap;
        typemap.emplace(token_bool, asn1_entity_boolean);
        typemap.emplace(token_int, asn1_entity_integer);
        typemap.emplace(token_bitstring, asn1_entity_bitstring);
        typemap.emplace(token_octstring, asn1_entity_octstring);
        typemap.emplace(token_null, asn1_entity_null);
        typemap.emplace(token_real, asn1_entity_real);
        typemap.emplace(token_ia5string, asn1_entity_ia5string);
        typemap.emplace(token_visiblestring, asn1_entity_visiblestring);

        for (auto& pair : result) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            parser::search_result res;
            ctx.psearch_result(res, range);

            _logger->writeln("pos [%zi] pattern[%2i] %.*s", range.begin, pid, (unsigned)res.size, res.p);
            ctx.for_each(res, dump_handler);

            token_description desc;
            asn1_entity_t type;

            // pattern to asn1_object*
            switch (pid) {
                case 0:  // $pattern_builtintype
                    ctx.get(res.begidx, &desc);
                    type = typemap[desc.tag];
                    *object << new asn1_builtin_type(type);
                    break;
            }
            object->publish(&bs);
            object->clear();
            _logger->write(bs);
        }

        _test_case.assert(res.match, __FUNCTION__, item.note);

        bs.clear();
    }
    object->release();
}

void test_x690_annex_a_1() {
#if 0
    _test_case.begin("X.690 A.1");

    // PersonnelRecord ::= [APPLICATION 0] IMPLICIT SET {
    //      name Name,
    //      title [0] VisibleString,
    //      number EmployeeNumber,
    //      dateOfHire [1] Date,
    //      nameOfSpouse [2] Name,
    //      children [3] IMPLICIT SEQUENCE OF ChildInformation DEFAULT {}}
    // ChildInformation ::= SET {name Name, dateOfBirth [0] Date}
    // Name ::= [APPLICATION 1] IMPLICIT SEQUENCE {givenName VisibleString, initial VisibleString, familyName VisibleString}
    // EmployeeNumber ::= [APPLICATION 2] IMPLICIT  INTEGER
    // Date ::= [APPLICATION 3] IMPLICIT  VisibleString

    {
        asn1* object = new asn1;

        (*object)
            // auto node_personal = new asn1_set("PersonnelRecord", new asn1_tag(asn1_class_application, 0, asn1_implicit));
            // *node_personal << new asn1_builtin_type("name", new asn1_builtin_type("Name", asn1_entity_referenced_type))                  //
            //                << new asn1_builtin_type("title", asn1_entity_visiblestring, new asn1_tag(asn1_class_context, 0))  //
            //                << new asn1_builtin_type("number", new asn1_builtin_type("EmployeeNumber", asn1_entity_referenced_type))
            //                << new asn1_builtin_type("dateOfHire", new asn1_builtin_type("Date", asn1_entity_referenced_type, new asn1_tag(asn1_class_context, 1)))
            //                << new asn1_builtin_type("nameOfSpouse", new asn1_builtin_type("Name", asn1_entity_referenced_type, new asn1_tag(asn1_class_context, 2)))
            //                << new asn1_builtin_type("children", &(new asn1_sequence_of("ChildInformation", new asn1_tag(asn1_class_context, 3,
            //                asn1_implicit)))->as_default());
            // *object << node_personal;
            .add(new asn1_set("PersonnelRecord", new asn1_tag(asn1_class_application, 0, asn1_implicit)),
                 [](asn1_set* set) -> void {
                     (*set) << new asn1_builtin_type("name", new asn1_builtin_type("Name", asn1_entity_referenced_type))
                            << new asn1_builtin_type("title", asn1_entity_visiblestring, new asn1_tag(asn1_class_context, 0))
                            << new asn1_builtin_type("number", new asn1_builtin_type("EmployeeNumber", asn1_entity_referenced_type))
                            << new asn1_builtin_type("dateOfHire", new asn1_builtin_type("Date", asn1_entity_referenced_type, new asn1_tag(asn1_class_context, 1)))
                            << new asn1_builtin_type("nameOfSpouse", new asn1_builtin_type("Name", asn1_entity_referenced_type, new asn1_tag(asn1_class_context, 2)))
                            << new asn1_builtin_type("children",
                                                  &(new asn1_sequence_of("ChildInformation", new asn1_tag(asn1_class_context, 3, asn1_implicit)))->as_default());
                 })
            // auto node_childinfo = new asn1_set("ChildInformation");
            // *node_childinfo << new asn1_builtin_type("name", new asn1_builtin_type("Name", asn1_entity_referenced_type))
            //                 << new asn1_builtin_type("dateOfBirth", new asn1_builtin_type("Date", asn1_entity_referenced_type, new asn1_tag(asn1_class_context, 0)));
            // *object << node_childinfo;
            .add(new asn1_set("ChildInformation"),  //
                 [](asn1_set* set) -> void {
                     (*set) << new asn1_builtin_type("name", new asn1_builtin_type("Name", asn1_entity_referenced_type))
                            << new asn1_builtin_type("dateOfBirth", new asn1_builtin_type("Date", asn1_entity_referenced_type, new asn1_tag(asn1_class_context, 0)));
                 })
            // auto node_name = new asn1_sequence("Name", new asn1_tag(asn1_class_application, 1, asn1_implicit));
            // *node_name << new asn1_builtin_type("givenName", new asn1_builtin_type(asn1_entity_visiblestring)) << new asn1_builtin_type("initial", new
            // asn1_object(asn1_entity_visiblestring))
            //            << new asn1_builtin_type("familyName", new asn1_builtin_type(asn1_entity_visiblestring));
            // *object << node_name;
            .add(new asn1_sequence("Name", new asn1_tag(asn1_class_application, 1, asn1_implicit)),  //
                 [](asn1_sequence* seq) -> void {
                     (*seq) << new asn1_builtin_type("givenName", new asn1_builtin_type(asn1_entity_visiblestring))  //
                            << new asn1_builtin_type("initial", new asn1_builtin_type(asn1_entity_visiblestring))    //
                            << new asn1_builtin_type("familyName", new asn1_builtin_type(asn1_entity_visiblestring));
                 })
            // auto node_employeenumber = new asn1_builtin_type("EmployeeNumber", asn1_entity_integer, new asn1_tag(asn1_class_application, 2, asn1_implicit));
            // *object << node_employeenumber;
            .add(new asn1_builtin_type("EmployeeNumber", asn1_entity_integer, new asn1_tag(asn1_class_application, 2, asn1_implicit)))
            // auto node_date = new asn1_builtin_type("Date", asn1_entity_visiblestring, new asn1_tag(asn1_class_application, 3, asn1_implicit));
            // *object << node_date;
            .add(new asn1_builtin_type("Date", asn1_entity_visiblestring, new asn1_tag(asn1_class_application, 3, asn1_implicit)));

        basic_stream bs1;
        basic_stream bs2;

        // publish
        {
            object->publish(&bs1);
            _logger->colorln("compose");
            _logger->write(bs1);
        }

        // clone
        asn1* n = nullptr;
        __try2 {
            n = object->clone();

            binary_t bin;
            n->publish(&bs2);
            _logger->colorln("clone");
            _logger->write(bs2);
        }
        __finally2 {
            n->release();
            _test_case.assert(bs1 == bs2, __FUNCTION__, "publish");
        }

        object->release();
    }
#endif
}

void test_x690_annex_a_2() {
    //
    //
}

void testcase_asn1() {
    // studying ...
    test_x690_8_1_2_identifier_octects();
    test_x690_8_1_3_length_octets();
    test_x690_8_1_5_end_of_contents();
    test_x690_encoding_value();
    test_x690_encoding_typevalue();
    test_x690_constructed();
    test_x690_8_9_sequence();
    test_testvector_chatgpt();
    test_x690_time();
    test_asn1_object();

    // TODO
    test_x690_annex_a_1();
    test_x690_annex_a_2();
}
