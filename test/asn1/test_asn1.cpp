/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

#define TESTVECTOR_ENTRY(e1, e2) \
    { e1, e2 }
#define TESTVECTOR_ENTRY3(e1, e2, e3) \
    { e1, e2, e3 }
#define TESTVECTOR_ENTRY4(e1, e2, e3, e4) \
    { e1, e2, e3, e4 }

// X.690 8.1.3 Length octets
void test_x690_8_1_3_length_octets() {
    _test_case.begin("ITU-T X.690 8.1.3");
    struct testvector {
        uint32 i;
        const char* expect;
    } _table[] = {
        TESTVECTOR_ENTRY(38, "26"),         TESTVECTOR_ENTRY(50, "32"),          TESTVECTOR_ENTRY(100, "64"),    TESTVECTOR_ENTRY(127, "7f"),
        TESTVECTOR_ENTRY(128, "81 80"),     TESTVECTOR_ENTRY(200, "81 c8"),      TESTVECTOR_ENTRY(201, "81 c9"), TESTVECTOR_ENTRY(300, "82 01 2c"),
        TESTVECTOR_ENTRY(1024, "82 04 00"), TESTVECTOR_ENTRY(65535, "82 ff ff"),
    };

    binary_t bin;

    auto encode_length_octet_routine = [&](const testvector& entry, binary_t& bin) -> void { t_asn1_length_octets<uint32>(bin, entry.i); };

    for (auto entry : _table) {
        encode_length_octet_routine(entry, bin);

        {
            test_case_notimecheck notimecheck(_test_case);

            _logger->writeln("%i -> %s", entry.i, base16_encode(bin).c_str());
            bool test = (bin == base16_decode_rfc(entry.expect));
            _test_case.assert(test, __FUNCTION__, "X.690 8.1.3 length octets [%i] expect [%s]", entry.i, entry.expect);
            bin.clear();
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
        variant var;
        const char* expect;
        const char* text;
        int debug;
    } _table[] = {
        TESTVECTOR_ENTRY3(variant(), "05 00", "X.690 8.8"),
        TESTVECTOR_ENTRY3(variant(true), "0101ff", "X.690 8.2"),
        TESTVECTOR_ENTRY3(variant(false), "010100", "X.690 8.2"),

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

        TESTVECTOR_ENTRY3(variant(0), "02 01 00", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(123), "02 01 7b", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(127), "02 01 7f", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(128), "02 02 00 80", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(129), "02 02 00 81", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(255), "02 02 00 ff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(256), "02 02 01 00", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(257), "02 02 01 01", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(300), "02 02 01 2c", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(1000), "02 02 03 e8", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(32767), "02 02 7f ff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(32768), "02 03 00 80 00", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(32769), "02 03 00 80 01", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(65534), "02 03 00 ff fe", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(65535), "02 03 00 ff ff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(65536), "02 03 01 00 00", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(65537), "02 03 01 00 01", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(16777215), "02 04 00 ff ff ff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(123456789), "02 04 07 5B CD 15", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(2147483647), "02 04 7f ff ff ff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(4294967295), "020500ffffffff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(4294967296), "02 05 01 00 00 00 00", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(1099511627775), "02 06 00 ff ff ff ff ff", "x.690 8.3"),
        TESTVECTOR_ENTRY4(variant(1152921504606846975), "02080fffffffffffffff", "x.690 8.3", 1),
        TESTVECTOR_ENTRY4(variant(1152921504606846976), "02081000000000000000", "x.690 8.3", 1),
        TESTVECTOR_ENTRY3(variant(-1), "02 01 ff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-10), "02 01 f6", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-126), "02 01 82", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-127), "02 01 81", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-128), "02 01 80", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-129), "02 02 ff 7f", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-136), "02 02 ff 78", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-256), "02 02 ff 00", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-257), "02 02 fe ff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-300), "02 02 fe d4", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-1234), "02 02 fb 2e", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-32768), "02 02 80 00", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-32769), "02 03 ff 7f ff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-8388607), "02 03 80 00 01", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-16777216), "02 04 ff 00 00 00", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-16777217), "02 04 fe ff ff ff", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-4294967296), "02 05 ff 00 00 00 00", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-1099511627775), "02 06 ff 00 00 00 00 01", "x.690 8.3"),
        TESTVECTOR_ENTRY3(variant(-1099511627776), "02 06 ff 00 00 00 00 00", "x.690 8.3"),

        TESTVECTOR_ENTRY3(variant(0.0f), "0900", "X.690 8.5"),
        // e -20 m 129453.0
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090580ec01f9ad'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [0.12345600128173828]>, b'')
        TESTVECTOR_ENTRY3(variant(0.123456), "090580ec01f9ad", "X.690 8.5"),
        // 2^-3 + 2^-5 -> 0.00101 -> 1.01 * 2^-3 (IEEE754) -> 101 * 2^-5
        TESTVECTOR_ENTRY3(variant(0.15625), "090380fb05", "X.690 8.5"),
        // 2^-1 (IEEE754) -> 0.1 -> 1.0 * 2^-1 (IEEE754)
        // >>> encode(univ.Real(0.5)).hex()
        // '09050335452d31'
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090380FF01'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [0.5]>, b'')
        TESTVECTOR_ENTRY3(variant(0.5), "090380FF01", "X.690 8.5"),
        // 2^-1 + 2^-2 -> 0.11 -> 1.1 * 2^-1 (IEEE754) -> 11 * 2^-2 (ASN.1)
        TESTVECTOR_ENTRY3(variant(0.75), "090380fe03", "X.690 8.5"),
        // 1.0 * 2^0 (IEEE754) -> 80 00 01
        TESTVECTOR_ENTRY3(variant(1.0), "0903800001", "X.690 8.5"),
        // e -21 m 2579497.0
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090580EB275C29'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [1.2300000190734863]>, b'')
        TESTVECTOR_ENTRY3(variant(1.23), "090580EB275C29", "X.690 8.5"),
        // 2^1 -> 10 -> 1.0 * 2^1 (IEEE754) -> 80 01 01
        TESTVECTOR_ENTRY3(variant(2.0), "0903800101", "X.690 8.5"),
        // 2^5 + 2^-2 + 2^2-4 -> 100000.0101 -> 1.000000101 * 2^5 (IEEE754) -> 1000000101 * 2^-4
        TESTVECTOR_ENTRY3(variant(32.3125), "090480fc0205", "X.690 8.5"),
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090680ef009dcccd'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [78.9000015258789]>, b'')
        TESTVECTOR_ENTRY3(variant(78.90), "090680ef009dcccd", "X.690 8.5"),
        TESTVECTOR_ENTRY3(variant(123.0), "090380007b", "X.690 8.5"),
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090680ef00f6e979'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [123.45600128173828]>, b'')
        TESTVECTOR_ENTRY3(variant(123.456), "090680ef00f6e979", "X.690 8.5"),
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('090680f600c0e6b7'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [12345.6787109375]>, b'')
        TESTVECTOR_ENTRY3(variant(12345.6789), "090680f600c0e6b7", "X.690 8.5"),
        // (-1)^1 * 1.0 * 2^0 (IEEE754) -> c0 00 01
        TESTVECTOR_ENTRY3(variant(-1.0), "0903c00001", "X.690 8.5"),
        // >>> print("Decoded REAL:", decode(binascii.unhexlify('0905c0eb275c29'), asn1Spec=univ.Real()))
        // Decoded REAL: (<Real value object, tagSet <TagSet object, tags 0:0:9>, payload [-1.2300000190734863]>, b'')
        TESTVECTOR_ENTRY3(variant(-1.23), "0905c0eb275c29", "X.690 8.5"),
        TESTVECTOR_ENTRY3(variant(-456.0), "0903c00339", "X.690 8.5"),  //
        TESTVECTOR_ENTRY3(variant(fp32_from_binary32(fp32_pinf)), "090140", "X.690 8.5 Inf"),
        TESTVECTOR_ENTRY3(variant(fp32_from_binary32(fp32_ninf)), "090141", "X.690 8.5 -Inf"),
        TESTVECTOR_ENTRY3(variant(fp32_from_binary32(fp32_nan)), "090142", "X.690 8.5 NaN"),
        TESTVECTOR_ENTRY3(variant(-0.0f), "090143", "X.690 8.5 -0.0"),
        TESTVECTOR_ENTRY3(variant(fp64_from_binary64(fp64_pinf)), "090140", "X.690 8.5 Inf"),
        TESTVECTOR_ENTRY3(variant(fp64_from_binary64(fp64_ninf)), "090141", "X.690 8.5 -Inf"),
        TESTVECTOR_ENTRY3(variant(fp64_from_binary64(fp64_nan)), "090142", "X.690 8.5 NaN"),
        TESTVECTOR_ENTRY3(variant(-0.0), "090143", "X.690 8.5 -0.0"),
    };

    _test_case.reset_time();

    binary_t bin;
    asn1_encode enc;

    auto encode_routine = [&](binary_t& bin, const variant& v) -> void { enc.encode(bin, asn1_type_primitive, v); };

    for (auto entry : _table) {
        encode_routine(bin, entry.var);

        {
            test_case_notimecheck notimecheck(_test_case);

            _logger->writeln("%s", base16_encode(bin).c_str());

            binary_t bin_expect = base16_decode_rfc(entry.expect);
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
    }
}

void dump_asn1(asn1* object, const char* expect, const char* text) {
    if (object && expect && text) {
        basic_stream bs;
        binary_t bin;

        object->publish(&bs);
        object->publish(&bin);

        _logger->write(bs);
        _logger->writeln("%s", base16_encode(bin).c_str());
        _test_case.assert(bin == base16_decode_rfc(expect), __FUNCTION__, "%s [%s]", text, expect);
    }
}

void test_x690_encoding_typevalue() {
    _test_case.begin("ITU-T X.690 type and value");

    // X.690 8.14 encoding of a tagged value
    auto type1 = new asn1_object(asn1_type_visiblestring);
    auto type2 = new asn1_object(asn1_type_visiblestring, new asn1_tag(asn1_class_application, 3, asn1_implicit));
    auto type3 = new asn1_composite(asn1_type_constructed, type2->clone(), new asn1_tag(2));
    auto type4 = new asn1_composite(asn1_type_constructed, type3->clone(), new asn1_tag(asn1_class_application, 7, asn1_implicit));
    auto type5 = new asn1_composite(asn1_type_primitive, type2->clone(), new asn1_tag(2, asn1_implicit));

    struct testvector {
        asn1_object* obj;
        variant var;
        const char* expect;
        const char* text;
    } _table[] = {
        // X.690 8.2
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_boolean), variant(true), "01 01 ff", "X.690 8.2 true"),

        // X.690 8.3
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_integer), variant(128), "02 02 00 80", "X.690 8.3 128"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_integer), variant(300), "02 02 01 2c", "X.690 8.3 300"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_integer), variant(-127), "02 01 81", "X.690 8.3 -127"),

        // X.690 8.5
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_real), variant(1.0), "0903800001", "X.690 8.5 1.0"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_real), variant(-1.0), "0903c00001", "X.690 8.5 -1.0"),

        // X.690 8.6 encoding of a bitstring value
        // commencing with the leading bit and proceeding to the trailing bit
        // if(size(input) % 2) { pad = '0'; padbit = 4; }
        // encode(asn1_tag_bitstring).encode(padbit).encode(input).encode(pad)
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_bitstring), variant("0a3b5f291cd"), "03 07 04 0A 3B 5F 29 1C D0", "X.690 8.6 0a3b5f291cd"),

        // X.690 8.7
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_octstring), variant("0123456789abcdef"), "04 08 01 23 45 67 89 ab cd ef", "X.690 8.7.4 0123456789abcdef"),

        // X.690 8.8
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_null), variant(), "05 00", "X.690 8.8 null"),

        // X.690 8.9
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_ia5string), variant("Smith"), "16 05 53 6d 69 74 68", "X.690 8.9 Smith"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_ia5string), variant("test1@rsa.com"), "16 0d 74 65 73 74 31 40 72 73 61 2e 63 6f 6d",
                          "X.690 8.9 test1@rsa.com"),

        // X.690 11.7 generalized time
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_generalizedtime), variant(datetime_t(1992, 5, 21, 0, 0, 0)),
                          "18 0F 31 39 39 32 30 35 32 31 30 30 30 30 30 30 5A", "X.690 11.7 #1"),  // 19920521000000Z
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_generalizedtime), variant(datetime_t(1992, 6, 22, 12, 34, 21)),
                          "18 0F 31 39 39 32 30 36 32 32 31 32 33 34 32 31 5A", "X.690 11.7 #2"),  // 19920622123421Z
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_generalizedtime), variant(datetime_t(1992, 7, 22, 13, 21, 00, 3)),
                          "18 11 31 39 39 32 30 37 32 32 31 33 32 31 30 30 2E 33 5A", "X.690 11.7 #3"),  // 19920722132100.3Z

        // X.690 8.14 encoding of a tagged value
        // case 1. Type1 ::= VisibleString
        TESTVECTOR_ENTRY4(type1, variant("Jones"), "1A 05 4A 6F 6E 65 73", "X.690 8.14 Type1"),
        // case 2. Type2 ::= [Application 3] implicit Type1
        TESTVECTOR_ENTRY4(type2, variant("Jones"), "43 05 4A 6F 6E 65 73", "X.690 8.14 Type2"),
        // case 3. Type3 ::= [2] Type2
        TESTVECTOR_ENTRY4(type3, variant("Jones"), "a2 07 43 05 4A 6F 6E 65 73", "X.690 8.14 Type3"),
        // case 4. Type4 ::= [Application 7] implicit Type3
        TESTVECTOR_ENTRY4(type4, variant("Jones"), "67 07 43 05 4A 6F 6E 65 73", "X.690 8.14 Type4"),
        // case 5. Type5 ::= [2] implicit Type2
        TESTVECTOR_ENTRY4(type5, variant("Jones"), "82 05 4A 6F 6E 65 73", "X.690 8.14 Type5"),

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
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_objid), variant("1.3.6.1.4.1"), "06 05 2b 06 01 04 01", "X.690 8.19 OID #1"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_objid), variant("1.2.840.113549"), "06 06 2A 86 48 86 F7 0d", "X.690 8.19 OID #2"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_objid), variant("1.3.6.1.4.1.311.21.20"), "06 09 2b 06 01 04 01 82 37 15 14", "X.690 8.19 OID #3"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_objid), variant("1.3.6.1.4.1.311.60.2.1.1"), "06 0B 2B 06 01 04 01 82 37 3C 02 01 01", "X.690 8.19 OID #4"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_objid), variant("1.2.840.10045.3.1.7"), "06 08 2a 86 48 ce 3d 03 01 07", "X.690 8.19 #5"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_objid), variant("2.100.3"), "06 03 81 34 03", "X.690 8.19 OID #6"),  // 0..39 < 100 ??
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_objid), variant("2.154"), "06 02 81 6a", "X.690 8.19 OID #7"),

        // X.690 8.20 encoding of a relative object identifier value
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_reloid), variant("8571.3.2"), "0D 04 C27B0302", "X.690 8.20 relative object identifier"),

        // X.690 8.21.5.4 Example Name ::= VisibleString
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_visiblestring), variant("Jones"), "1a 05 4a6f6e6573", "X.690 8.21 VisibleString"),
        // X.690 8.23
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_printstring), variant("Test User 1"), "13 0b 54 65 73 74 20 55 73 65 72 20 31",
                          "X.690 8.23 PrintableString"),
        TESTVECTOR_ENTRY4(new asn1_object(asn1_type_t61string), variant("cl'es publiques"), "14 0f 63 6c 27 65 73 20 70 75 62 6c 69 71 75 65 73",
                          "X.690 8.23 T61String"),  // // replace Â C2 for ' 27
    };

    for (auto item : _table) {
        asn1* object = new asn1;
        *object << item.obj;
        object->set_value_byindex(0, std::move(item.var));
        dump_asn1(object, item.expect, item.text);
        object->release();
    }
}

void test_x690_constructed() {
    _test_case.begin("ITU-T X.690 constructed");

    // constructed
    // X.690 10.2 String encoding forms
    // For bitstring, octetstring and restricted character string types, the constructed form of encoding shall not be used. (Contrast with 8.23.6.)
    {
        binary bin;
        bin.push_back(asn1_tag_bitstring | asn1_tag_constructed);
        bin.push_back(0x80);
        bin.push_back(asn1_tag_bitstring);
        t_asn1_length_octets<uint32>(bin.get(), 3);
        bin.append(base16_decode("000a3b"));
        bin.push_back(asn1_tag_bitstring);
        t_asn1_length_octets<uint32>(bin.get(), 5);
        bin.append(base16_decode("045f291cd0"));
        bin.push_back(0x00);  // EOC
        bin.push_back(0x00);  // EOC
        _logger->writeln("%s", base16_encode(bin.get()).c_str());
        const char* expect_constructed = "23 80 03 03 00 0A 3B 03 05 04 5F 29 1C D0 00 00";
        _test_case.assert(bin.get() == base16_decode_rfc(expect_constructed), __FUNCTION__, "X.690 8.6.4 BitString constructed");
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

    // SEQUENCE {name IA5String , ok BOOLEAN }
    {
        basic_stream bs;

        constexpr char type[] = R"(SEQUENCE {name IA5String, ok BOOLEAN})";
        constexpr char value[] = R"({name "Smith", ok TRUE})";
        constexpr char expect[] = "300a1605536d6974680101ff";

        auto seq = new asn1_sequence;
        *seq << new asn1_object("name", asn1_type_ia5string) << new asn1_object("ok", asn1_type_boolean);
        notation << seq;
        notation.publish(&bs);
        _logger->write(bs);
    }

    // 00000000 : 30 0A 16 05 53 6D 69 74 68 01 01 FF -- -- -- -- | 0...Smith...
    {
        binary_t bin;
        bin.insert(bin.end(), asn1_class_universal | asn1_tag_constructed | asn1_tag_sequence);
        size_t pos = bin.size();
        enc.ia5string(bin, "Smith");
        enc.primitive(bin, true);
        size_t size = bin.size() - pos;  // 0xa
        bin.insert(bin.begin() + pos, size);

        _logger->writeln("%s", base16_encode(bin).c_str());
        _test_case.assert(bin == base16_decode_rfc("30 0A 16 05 53 6D 69 74 68 01 01 FF"), __FUNCTION__, "X.690 8.9 Sequence");
    }

#if 0
    {
        basic_stream bs;
        binary_t bin;
        auto n = notation.clone();
        n->set_value_byname("name", "Smith").set_value_byname("ok", true);
        n->publish(&bin);
        n->publish(&bs);
        n->release();
        _logger->write(bs);
        _logger->writeln("%s", base16_encode(bin).c_str());
    }
#endif
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
    // $pattern_builtintype
    //     new asn1_object(builtintype)
    // [$pattern_class 1] $pattern_taggedmode $pattern_builtintype
    //     new asn1_object(builtintype, new asn1_tag(asn1_class_application, 3, asn1_implicit)));
    // lvalue ::= $pattern_builtintype
    //     new asn1_object(lvalue, builtintype, new asn1_tag(asn1_class_application, 3, asn1_implicit)));
    // name $pattern_builtintype
    //     new asn1_object(name, new asn1_object(builtintype, new asn1_tag(asn1_class_application, 3, asn1_implicit))));
    struct testvector2 {
        const char* note;
        asn1_object* asn1obj;
    };
    testvector2 table2[] = {
        {"NULL", new asn1_object(asn1_type_null)},
        {"INTEGER", new asn1_object(asn1_type_integer)},
        {"REAL", new asn1_object(asn1_type_real)},
        {"SEQUENCE {name IA5String, ok BOOLEAN}", new asn1_sequence(2, new asn1_object("name", asn1_type_ia5string), new asn1_object("ok", asn1_type_boolean))},
        {"Date ::= VisibleString", new asn1_object("Date", asn1_type_visiblestring)},
        {"Date ::= [APPLICATION 3] IMPLICIT VisibleString",
         new asn1_object("Date", asn1_type_visiblestring, new asn1_tag(asn1_class_application, 3, asn1_implicit))},
    };

    basic_stream bs;
    asn1* object = new asn1;
    for (auto item : table2) {
        *object << item.asn1obj;
        object->publish(&bs);
        object->clear();
        _logger->write(bs);

        // compare
        parser p;
        parser::context ctx;
        parser::search_result res;
        p.parse(ctx, item.note);
        res = p.wsearch(ctx, bs);
        bs.clear();

        auto result = p.psearchex(ctx);
        auto dump_handler = [&](const token_description* desc) -> void {
            _logger->writeln("> type %d(%s) tag %i index %d pos %zi len %zi (%.*s)", desc->type, p.typeof_token(desc->type).c_str(), desc->tag, desc->index,
                             desc->pos, desc->size, (unsigned)desc->size, desc->p);
        };
        std::map<uint32, asn1_type_t> typemap;
        typemap.insert({token_bool, asn1_type_boolean});
        typemap.insert({token_int, asn1_type_integer});
        typemap.insert({token_bitstring, asn1_type_bitstring});
        typemap.insert({token_octstring, asn1_type_octstring});
        typemap.insert({token_null, asn1_type_null});
        typemap.insert({token_real, asn1_type_real});
        typemap.insert({token_ia5string, asn1_type_ia5string});
        typemap.insert({token_visiblestring, asn1_type_visiblestring});

        for (auto& pair : result) {
            // pair(pos_occurrence, id_pattern)
            const auto& range = pair.first;
            const auto& pid = pair.second;
            parser::search_result res;
            ctx.psearch_result(res, range);

            _logger->writeln("pos [%zi] pattern[%2i] %.*s", range.begin, pid, (unsigned)res.size, res.p);
            ctx.for_each(res, dump_handler);

            token_description desc;
            asn1_type_t type;

            // pattern to asn1_object*
            switch (pid) {
                case 0:  // $pattern_builtintype
                    ctx.get(res.begidx, &desc);
                    type = typemap[desc.tag];
                    *object << new asn1_object(type);
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

        auto node_personal = new asn1_set("PersonnelRecord", new asn1_tag(asn1_class_application, 0, asn1_implicit));
        *node_personal << new asn1_object("name", new asn1_object("Name", asn1_type_referenced))
                       << new asn1_object("title", asn1_type_visiblestring, new asn1_tag(0))
                       << new asn1_object("number", new asn1_object("EmployeeNumber", asn1_type_referenced))
                       << new asn1_object("dateOfHire", new asn1_object("Date", asn1_type_referenced, new asn1_tag(1)))
                       << new asn1_object("nameOfSpouse", new asn1_object("Name", asn1_type_referenced, new asn1_tag(2)))
                       << new asn1_object("children", &(new asn1_sequence_of("ChildInformation", new asn1_tag(3, asn1_implicit)))->as_default());
        *object << node_personal;

        auto node_childinfo = new asn1_set("ChildInformation");
        *node_childinfo << new asn1_object("name", new asn1_object("Name", asn1_type_referenced))
                        << new asn1_object("dateOfBirth", new asn1_object("Date", asn1_type_referenced, new asn1_tag(0)));
        *object << node_childinfo;

        auto node_name = new asn1_sequence("Name", new asn1_tag(asn1_class_application, 1, asn1_implicit));
        *node_name << new asn1_object("givenName", new asn1_object(asn1_type_visiblestring))
                   << new asn1_object("initial", new asn1_object(asn1_type_visiblestring))
                   << new asn1_object("familyName", new asn1_object(asn1_type_visiblestring));
        *object << node_name;

        auto node_employeenumber = new asn1_object("EmployeeNumber", asn1_type_integer, new asn1_tag(asn1_class_application, 2, asn1_implicit));
        *object << node_employeenumber;

        auto node_date = new asn1_object("Date", asn1_type_visiblestring, new asn1_tag(asn1_class_application, 3, asn1_implicit));
        *object << node_date;

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
}

void test_x690_annex_a_2() {
    //
    //
}
