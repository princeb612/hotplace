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
using namespace hotplace::crypto;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {}
} OPTION;

t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_random() {
    _test_case.begin("random");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    uint32 value = 0;
    openssl_prng random;
    int i = 0;
    int times = 30;

    for (i = 0; i < times; i++) {
        value = random.rand32();
        if (option.verbose) {
            _logger->writeln("rand %08x", (int)value);
        }
    }

    _test_case.test(ret, __FUNCTION__, "random loop %i times", times);
}

void test_nonce() {
    _test_case.begin("random");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    std::string nonce;
    openssl_prng random;
    int i = 0;
    int times = 30;

    for (i = 0; i < times; i++) {
        nonce = random.nonce(16);
        if (option.verbose) {
            _logger->writeln("nonce.1 %s", nonce.c_str());
        }
    }
    for (i = 0; i < times; i++) {
        nonce = random.rand(16, encoding_t::encoding_base16, true);
        if (option.verbose) {
            _logger->writeln("nonce.2 %s", nonce.c_str());
        }
    }

    _test_case.test(ret, __FUNCTION__, "nonce loop %i times", times);
}

void test_token() {
    _test_case.begin("random");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    std::string token;
    openssl_prng random;
    int i = 0;
    int times = 30;

    for (i = 0; i < times; i++) {
        token = random.token(16);
        if (option.verbose) {
            _logger->writeln("token.1 %s", token.c_str());
        }
    }
    for (i = 0; i < times; i++) {
        token = random.rand(16, encoding_t::encoding_base64url, true);
        if (option.verbose) {
            _logger->writeln("token.2 %s", token.c_str());
        }
    }

    _test_case.test(ret, __FUNCTION__, "token loop %i times", times);
}

int main(int argc, char** argv) {
    set_trace_option(trace_option_t::trace_bt);
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    __try2 {
        openssl_startup();
        openssl_thread_setup();

        test_random();
        test_nonce();
        test_token();
    }
    __finally2 {
        openssl_thread_cleanup();
        openssl_cleanup();
    }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
