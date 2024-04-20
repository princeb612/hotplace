/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

typedef struct _OPTION {
    int debug;

    _OPTION() : debug(0) {}
} OPTION;

t_shared_instance<cmdline_t<OPTION> > cmdline;

void test_payload_dump() {
    OPTION& option = cmdline->value();
    _test_case.begin("payload");

    {
        payload pl;
        binary_t data = convert("data");
        binary_t pad = convert("pad");
        uint8 padlen = 3;  // "pad"
        basic_stream bs;
        binary_t bin_padded;
        binary_t bin_notpadded;

        pl << new payload_member(padlen, "padlen", "pad") << new payload_member(data, "data") << new payload_member((uint32)0x1000, true, "value")
           << new payload_member(pad, "pad", "pad");

        pl.set_group("pad", true);  // enable "pad" group
        pl.dump(bin_padded);
        if (option.debug) {
            dump_memory(bin_padded, &bs);
            printf("%s\n", bs.c_str());
        }
        _test_case.assert(12 == bin_padded.size(), __FUNCTION__, "payload padded");  // 3 || "data" || 0x1000 || "pad"

        pl.set_group("pad", false);  // disable "pad" group
        pl.dump(bin_notpadded);
        if (option.debug) {
            dump_memory(bin_notpadded, &bs);
            printf("%s\n", bs.c_str());
        }
        _test_case.assert(8 == bin_notpadded.size(), __FUNCTION__, "payload not padded");  // "data" || 0x1000
    }
}

void test_payload_parse() {
    OPTION& option = cmdline->value();
    _test_case.begin("payload");

    {
        payload pl;
        binary_t data;
        binary_t pad;
        pl << new payload_member((uint8)0, "padlen", "pad") << new payload_member(data, "data") << new payload_member((uint32)0, true, "value")
           << new payload_member(pad, "pad", "pad");
        binary_t decoded = base16_decode("036461746100001000706164");
        pl.set_reference_value("pad", "padlen").read(decoded);
        binary_t bin_dump;
        pl.dump(bin_dump);
        _test_case.assert(bin_dump == decoded, __FUNCTION__, "read/parse");
    }
}

void test_payload_uint24() {
    OPTION& option = cmdline->value();
    _test_case.begin("payload");

    binary_t pad = convert("pad");
    binary_t bin_payload;
    binary_t expect = base16_decode("0310000010000000706164");

    {
        payload pl;
        uint8 padlen = 3;  // "pad"
        basic_stream bs;
        uint32_24_t i32_24(0x100000);  // 32/24 [0 .. 0x00ffffff]
        uint32 i32 = 0x10000000;       // 32/32 [0 .. 0xffffffff]

        pl << new payload_member(padlen, "padlen") << new payload_member(i32_24, "int32_24") << new payload_member(i32, true, "int32_32")
           << new payload_member(pad, "pad");

        pl.dump(bin_payload);
        if (option.debug) {
            dump_memory(bin_payload, &bs);
            printf("%s\n", bs.c_str());
        }
        _test_case.assert(expect == bin_payload, __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)
    }

    {
        payload pl;
        uint32_24_t i32_24;
        pl << new payload_member((uint8)0, "padlen") << new payload_member(i32_24, "int32_24") << new payload_member((uint32)0, true, "int32_32")
           << new payload_member(pad, "pad");

        pl.read(expect);

        uint8 padlen = t_variant_to_int<uint8>(pl.select("padlen")->get_variant().content());
        uint32_24_t i24 = t_variant_to_int<uint32>(pl.select("int32_24")->get_variant().content());
        uint32 i32 = t_variant_to_int<uint32>(pl.select("int32_32")->get_variant().content());

        if (option.debug) {
            uint32 i24_value = i24.get();
            printf("padlen %u i32_b24 %u (0x%08x) uint32_32 %u (0x%08x)\n", padlen, i24_value, i24_value, i32, i32);
        }

        _test_case.assert(0x100000 == i24.get(), __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)

        binary_t bin_dump;
        pl.dump(bin_dump);
        _test_case.assert(expect == bin_dump, __FUNCTION__, "payload /w i32_b24");  // 3(1) || i32_24(3) || i32_32(4) || "pad"(3)
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif
    cmdline.make_share(new cmdline_t<OPTION>);

    *cmdline << cmdarg_t<OPTION>("-d", "debug", [&](OPTION& o, char* param) -> void { o.debug = 1; }).optional();

    cmdline->parse(argc, argv);
    OPTION& option = cmdline->value();

    test_payload_dump();
    test_payload_parse();
    test_payload_uint24();

    _test_case.report(5);
    cmdline->help();
    return _test_case.result();
}
