#ifndef __HOTPLACE_TEST_ENCODE__
#define __HOTPLACE_TEST_ENCODE__

#include <sdk/sdk.hpp>
#include <test/test.hpp>

enum {
    decode_b64u = 1,
    decode_b64 = 2,
    decode_b16 = 3,
    encode_plaintext = 4,
    encode_b16_rfc = 5,
};
struct OPTION : public CMDLINEOPTION {
    int mode;
    std::string content;
    std::string filename;

    OPTION() : CMDLINEOPTION(), mode(0) {}

    void set(int m, char* param) {
        mode = m;
        if (param) {
            content = param;
        }
    }
    void setfile(char* param) {
        if (param) {
            filename = param;
        }
    }
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test_base16();
void test_base16_func();
void test_base16_decode();
void test_base16_oddsize();
void test_base16_rfc();

void test_base64();

#endif
