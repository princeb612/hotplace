/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * studying
 *
 */

#include <algorithm>
#include <functional>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

// ISO/IEC 8824-1
// ITU-T X.680
// 8 Tags
// Table 1 - Universal class tag assignment

// ISO/IEC 8825-1
// X.690
// Specificaton of basic notation
// 8 Basic encoding rules
// 8.1 General rules for encoding
// 8.1.1 structure of an encoding
//  Table 1 - Encoding of class of tag
//  Figure 2 - An alternative constructed encoding
// 8.1.2 identifier octets
//  Figure 3 - Identifier octet (low tag number)
//  Figure 4 - Identifier octets (high tag number)
// 8.1.3 length octets
// 8.1.4 contents octets
// 8.1.5 end-of-contents octets
// 8.2 Encoding of a boolean value
// 8.3 Encoding of an integer value
// 8.4 Encoding of an enumerated value
// 8.5 Encoding of a real value

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION>> _cmdline;

// X.680 8.4 Table 1 – Universal class tag assignments
enum asn1_universal_class_tag {
    asn1_tag_boolean = 1,
    asn1_tag_integer = 2,
    asn1_tag_bitstring = 3,
    asn1_tag_octstring = 4,
    asn1_tag_null = 5,
    asn1_tag_objid = 6,
    asn1_tag_objdesc = 7,
    asn1_tag_extern = 8,
    asn1_tag_real = 9,
    asn1_tag_enum = 10,
    asn1_tag_embedpdv = 11,
    asn1_tag_utf8string = 12,
    asn1_tag_relobjid = 13,
    // asn1_tag_sequence = 16,
    asn1_tag_set = 17,
    asn1_tag_string = 18,
    asn1_tag_ia5string = 0x16,  // IA5String
    asn1_tag_time = 23,
    asn1_tag_visiblestring = 0x1a,  // ISO646String)
    asn1_tag_sequence = 0x30,

    // X.680 8.1.2.2 Table 1 - encoding of class of tag
    // class            bit8 bit7
    // universal        0    0
    // application      0    1
    // context-specific 1    0
    // private          1    1
    asn1_tag_universal = 0x00,
    asn1_tag_application = 0x40,
    asn1_tag_context = 0x80,
    asn1_tag_private = 0xc0,

    // X.680 8.1.2.3 Figure 3 - identifier octet
    // identifier       bit6
    // primitive        0
    // constructed      1
    asn1_tag_primitive = 0x00,
    asn1_tag_constructed = 0x20,
};

// X.680 8.1.3 Length octets
// X.690 8.1.3 Length octets
template <typename type>
void encode_asn1_length(type v, binary_t& bin) {
    std::function<type(type)> conv;

    uint8 octets = sizeof(type);

    if (sizeof(int128) == octets) {
        conv = hton128;
    } else if (sizeof(int64) == octets) {
        conv = hton64;
    } else if (sizeof(int32) == octets) {
        conv = hton32;
    } else if (sizeof(int16) == octets) {
        conv = hton16;
    } else {
        conv = [](type v) -> type { return v; };
    }

    uint128 m = 0;
    for (uint8 i = 1; i <= octets; i++) {
        m <<= 8;
        m |= 0xff;
        if (v <= m) {
            if ((1 == i) && (v <= 0x7f)) {
                bin.insert(bin.end(), (uint8)v);
            } else {
                type be;
                if (is_big_endian()) {
                    be = v;
                } else {
                    be = conv(v);
                }

                uint8 leading = 0x80 | i;
                bin.insert(bin.end(), leading);
                bin.insert(bin.end(), (byte_t*)&be + (octets - i), (byte_t*)&be + octets);
            }
            break;
        }
    }
}

// X.680 8.1.2.4 Figure 4 identifier octets

// X.690 8.1.3 Length octets
void x690_8_1_3_length_octets() {
#define TESTVECTOR_ENTRY(ei, et) \
    { ei, et }
    struct table {
        uint32 i;
        const char* expect;
    } _table[] = {
        TESTVECTOR_ENTRY(38, "26"),
        TESTVECTOR_ENTRY(201, "81 c9"),
        TESTVECTOR_ENTRY(127, "7f"),
        TESTVECTOR_ENTRY(128, "81 80"),
    };

    binary_t bin;

    auto encode_length_octet_routine = [&](int i, const std::string& expect) -> void {
        bin.clear();
        encode_asn1_length<uint32>(i, bin);
        _test_case.assert(bin == base16_decode_rfc(expect), __FUNCTION__, "X.690 8.1.3 length octets %i", i);
    };

    for (auto entry : _table) {
        encode_length_octet_routine(entry.i, entry.expect);
    }
}

// X.690 8.1.5 end-of-contents octets
void x690_8_1_5_end_of_contents() {
    // 8.1.3.6 For the indefinite form, the length octets indicate that the contents octets are terminated by end-of-contents octets (see 8.1.5),
    // and shall consist of a single octet.

    // 8.1.3.6.1 The single octet shall have bit 8 set to one, and bits 7 to 1 set to zero.

    // X.690 8.1.3.6 For the indefinite form, the length octets indicate that the contents octets are terminated by end-of-contents octets (see 8.1.5),
    // and shall consist of a single octet.

    // 0x80 infinite length
    // ...
    // 0x00 0x00 (EOC)

    binary_t bin;
    bin.insert(bin.end(), 0x00);
    encode_asn1_length<uint32>(0, bin);
    _logger->dump(bin);
    _test_case.assert(bin == base16_decode("0000"), __FUNCTION__, "X.690 8.1.5 end-of-contents octets");
}

// X.690 8.2 encoding of a boolean value
void x690_8_2_boolean() {
    binary_t bin;
    bin.insert(bin.end(), asn1_tag_boolean);
    encode_asn1_length<uint32>(1, bin);
    bin.insert(bin.end(), 0xff);
    _logger->dump(bin);
    _test_case.assert(bin == base16_decode("0101ff"), __FUNCTION__, "X.690 8.2.2 true");

    bin.clear();
    bin.insert(bin.end(), asn1_tag_boolean);
    encode_asn1_length<uint32>(1, bin);
    bin.insert(bin.end(), 0x00);
    _logger->dump(bin);
    _test_case.assert(bin == base16_decode("010100"), __FUNCTION__, "X.690 8.2.2 false");
}

template <typename type>
void encode_asn1_integer(type v, binary_t& bin) {
    uint32 tsize = sizeof(type);
    type i = convert_endian(v);
    type p = v >= 0 ? v : ~v;
    type mask = 0;
    uint32 len = 1;

    for (uint32 i = tsize; i > 0; i--) {
        mask = (0xff << ((i - 1) * 8));
        if (mask & p) {  // check occupied bytes
            len = i;
            type msb = (1 << ((len * 8) - 1));
            if (msb & p) {  // msb set
                len += 1;
            }
            break;
        }
    }

    bin.insert(bin.end(), asn1_tag_integer);
    encode_asn1_length<uint32>(len, bin);
    bin.insert(bin.end(), (byte_t*)&i + (tsize - len), (byte_t*)&i + tsize);
}

void x690_8_3_integer() {
    // test vector ChatGPT provided
    struct table {
        int32 i;
        const char* expect;
    } _table[] = {
        TESTVECTOR_ENTRY(0, "02 01 00"),         TESTVECTOR_ENTRY(127, "02 01 7F"),          TESTVECTOR_ENTRY(128, "02 02 00 80"),
        TESTVECTOR_ENTRY(256, "02 02 01 00"),    TESTVECTOR_ENTRY(300, "02 02 01 2C"),       TESTVECTOR_ENTRY(65535, "02 03 00 FF FF"),
        TESTVECTOR_ENTRY(-1, "02 01 FF"),        TESTVECTOR_ENTRY(-128, "02 01 80"),         TESTVECTOR_ENTRY(-129, "02 02 FF 7F"),
        TESTVECTOR_ENTRY(-256, "02 02 FF 00"),   TESTVECTOR_ENTRY(-257, "02 02 FE FF"),      TESTVECTOR_ENTRY(-300, "02 02 FE D4"),
        TESTVECTOR_ENTRY(-32768, "02 02 80 00"), TESTVECTOR_ENTRY(-32769, "02 03 FF 7F FF"),
    };

    binary_t bin;

    auto encode_integer_routine = [&](int i, const std::string& expect) -> void {
        bin.clear();
        encode_asn1_integer<int32>(i, bin);
        _logger->dump(bin);
        _test_case.assert(bin == base16_decode_rfc(expect), __FUNCTION__, "X.690 8.3 integer %i expect %s", i, expect.c_str());
    };

    for (auto entry : _table) {
        encode_integer_routine(entry.i, entry.expect);
    }
}

void x690_8_5_real() {
    // test vector ChatGPT provided
    struct table {
        double f;
        const char* expect;
    } _table[] = {
        TESTVECTOR_ENTRY(1.23, "09 03 80 00 3F 9D 70"),
        TESTVECTOR_ENTRY(-1.23, "09 03 C0 00 3F 9D 70"),
        TESTVECTOR_ENTRY(0.0, "09 00"),                                // X.690 8.5.2
        TESTVECTOR_ENTRY(fp32_from_binary32(0x7f800000), "09 01 40"),  // inf
        TESTVECTOR_ENTRY(fp32_from_binary32(0xff800000), "09 01 41"),  // -inf
        TESTVECTOR_ENTRY(fp32_from_binary32(0x7fc00000), "09 01 42"),  // NaN
        TESTVECTOR_ENTRY(123.45, "09 05 80 02 3F F6 E6 66"),
        TESTVECTOR_ENTRY(12345.6789, "09 09 80 00 00 03 40 E6 B7 27 0A 14 7A E1"),
        TESTVECTOR_ENTRY(-0.000012345, "09 09 C0 FF FF FC 3D CC CC CC CC CC CC CD"),
    };

    binary_t bin;

    auto encode_float_routine = [&](double d, const std::string& expect) -> void {
        bin.clear();

        variant var;
        var.set_double(d);
        ieee754_as_small_as_possible(var, d);
        var.dump(bin, true);
        _logger->dump(bin);

        _test_case.test(errorcode_t::not_supported, __FUNCTION__, "X.690 8.5 real 0x%08x expect %s", var.content().data.d, expect.c_str());
    };

    for (auto entry : _table) {
        encode_float_routine(entry.f, entry.expect);
    }

    _logger->dump(bin);

    // _test_case.test(errorcode_t::not_supported, __FUNCTION__, "X.690 8.5 real");
}

// X.690 8.6 encoding of a bitstring value
// commencing with the leading bit and proceeding to the trailing bit
void x690_8_6_bitstring() {
    // sketch - pseudo code
    // if(size(input) % 2) { pad = '0'; padbit = 4; }
    // encode(asn1_tag_bitstring).encode(padbit).encode(input).encode(pad)

    // primitive
    {
        binary bin;
        bin.push_back(asn1_tag_bitstring);
        encode_asn1_length<uint32>(7, bin.get());  // '0A3B5F291CD'h || 0
        // X.690 8.6.2.2 The initial octet shall encode, as an unsigned binary integer with bit 1 as the least significant bit,
        // the number of unused bits in the final subsequent octet. The number shall be in the range zero to seven.
        bin.push_back(4);
        bin.append(base16_decode("0A3B5F291CD0"));
        _logger->dump(bin.get());
        _test_case.assert(bin.get() == base16_decode("0307040A3B5F291CD0"), __FUNCTION__, "X.690 8.6.4 BitString");
    }

    // constructed
    {
        binary bin;
        bin.push_back(asn1_tag_bitstring | asn1_tag_constructed);
        bin.push_back(0x80);
        bin.push_back(asn1_tag_bitstring);
        encode_asn1_length<uint32>(3, bin.get());
        bin.append(base16_decode("000a3b"));
        bin.push_back(asn1_tag_bitstring);
        encode_asn1_length<uint32>(5, bin.get());
        bin.append(base16_decode("045f291cd0"));
        bin.push_back(0x00);  // EOC
        bin.push_back(0x00);  // EOC
        _logger->dump(bin.get());
        const char* expect_constructed = "23 80 03 03 00 0A 3B 03 05 04 5F 29 1C D0 00 00";
        _test_case.assert(bin.get() == base16_decode_rfc(expect_constructed), __FUNCTION__, "X.690 8.6.4 BitString constructed");
    }
}

// X.690 8.8 encoding of a null value
void x690_8_8_null() {
    binary_t bin;
    bin.insert(bin.end(), asn1_tag_null);
    encode_asn1_length<uint32>(0, bin);
    _logger->dump(bin);
    _test_case.assert(bin == base16_decode("0500"), __FUNCTION__, "X.690 8.8 null");
}

// X.690 8.9 encoding of a sequence value
void x690_8_9_sequence() {
    // SEQUENCE {name IA5String, ok BOOLEAN}
    // {name "Smith", ok TRUE}
    binary_t bin;
    bin.insert(bin.end(), asn1_tag_ia5string);
    const char* name = "Smith";
    encode_asn1_length<uint32>(5, bin);
    bin << name;

    bin.insert(bin.end(), asn1_tag_boolean);
    encode_asn1_length<uint32>(1, bin);
    bin.insert(bin.end(), 0xff);

    size_t size = bin.size();
    bin.insert(bin.begin(), size);  // 0xa
    bin.insert(bin.begin(), asn1_tag_sequence);

    // Sequence Length  Contents
    // 30_16    0A_16
    //                  IA5String  Length  Contents
    //                  16_16      05_16   "Smith"
    //                  Boolean    Length  Contents
    //                  01_16      01_16   FF_16
    _logger->dump(bin);
    _test_case.assert(bin == base16_decode_rfc("30 0A 16 05 53 6D 69 74 68 01 01 FF"), __FUNCTION__, "X.690 8.9 Sequence");
}

// X.690 8.14 encoding of a tagged value
void x690_8_14_tagged() {
    binary_t bin_type1;
    binary_t bin_type2;
    binary_t bin_type3;
    binary_t bin_type4;
    binary_t bin_type5;
    // Type1 ::= VisibleString
    {
        binary_push(bin_type1, asn1_tag_visiblestring);
        encode_asn1_length<uint32>(5, bin_type1);
        binary_append(bin_type1, "Jones");
        _logger->dump(bin_type1);
        _test_case.assert(bin_type1 == base16_decode_rfc("1A 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # type1");
    }
    // Type2 ::= [Application 3] implicit Type1
    {
        binary_push(bin_type2, asn1_tag_application | 3);
        encode_asn1_length<uint32>(5, bin_type2);
        binary_append(bin_type2, "Jones");
        _logger->dump(bin_type2);
        _test_case.assert(bin_type2 == base16_decode_rfc("43 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # type2");
    }
    // Type3 ::= [2] Type2
    {
        binary_push(bin_type3, asn1_tag_context | asn1_tag_constructed | 2);
        encode_asn1_length<uint32>(bin_type2.size(), bin_type3);
        binary_append(bin_type3, bin_type2);
        _logger->dump(bin_type3);
        _test_case.assert(bin_type3 == base16_decode_rfc("a2 07 43 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # type3");
    }
    // Type4 ::= [Application 7] implicit Type3
    {
        binary_push(bin_type4, asn1_tag_application | asn1_tag_constructed | 7);
        encode_asn1_length<uint32>(bin_type2.size(), bin_type4);
        binary_append(bin_type4, bin_type2);  // ?? not bin_type3
        _logger->dump(bin_type4);
        _test_case.assert(bin_type4 == base16_decode_rfc("67 07 43 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # type4");
    }
    // Type5 ::= [2] implicit Type2
    {
        binary_push(bin_type5, asn1_tag_context | 2);
        encode_asn1_length<uint32>(5, bin_type5);
        binary_append(bin_type5, "Jones");
        _logger->dump(bin_type5);
        _test_case.assert(bin_type5 == base16_decode_rfc("82 05 4A 6F 6E 65 73"), __FUNCTION__, "X.690 8.14 tagged # Type5");
    }
}

// X.690 8.19 encoding of an object identifier value
void x690_8_19_objid() {
    // {joint-iso-itu-t 100 3}
    // {2 100 3}
    binary_t bin;
    binary_push(bin, asn1_tag_objid);
    encode_asn1_length<uint32>(3, bin);
    // 0x813403
    _logger->dump(bin);
    // 1.3.6.1.4.1 (0x2b 0x06 0x01 0x04 0x01 0x00)
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "X.690 8.19 object identifier");
}

// X.690 8.20 encoding of a relative object identifier value
void x690_8_20_relobjid() {
    //
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "X.690 8.20 relative object identifier");
}

// X.690 8.21.5.4 Example Name ::= VisibleString
void x690_8_21_visiblestring() {
    binary_t bin;
    const char* value = "Jones";
    size_t len = strlen(value);
    binary_push(bin, asn1_tag_visiblestring);
    encode_asn1_length<size_t>(len, bin);
    binary_append(bin, value);
    _logger->dump(bin);
    _test_case.assert(bin == base16_decode_rfc("1a 05 4a6f6e6573"), __FUNCTION__, "X.690 8.21 VisibleString");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    // studying ...
    x690_8_1_3_length_octets();
    x690_8_1_5_end_of_contents();
    x690_8_2_boolean();
    x690_8_3_integer();
    x690_8_5_real();
    x690_8_6_bitstring();
    x690_8_8_null();
    x690_8_9_sequence();
    x690_8_14_tagged();
    x690_8_19_objid();
    x690_8_20_relobjid();
    x690_8_21_visiblestring();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
