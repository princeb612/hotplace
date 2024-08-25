/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <algorithm>
#include <functional>
#include <sdk/nostd.hpp>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    std::string address;
    uint16 port;
    std::string message;

    _OPTION() : verbose(0), address("127.0.0.1"), port(9000), message("hello") {
        // do nothing
    }
} OPTION;
t_shared_instance<cmdline_t<OPTION>> _cmdline;

#define BUFFER_SIZE 1024

void client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    socket_t sock = -1;
    sockaddr_storage_t sock_storage;
    char buffer[BUFFER_SIZE];

    __try2 {
#if defined _WIN32 || defined _WIN64
        winsock_startup();
#endif

        ret = create_socket(&sock, &sock_storage, SOCK_DGRAM, option.address.c_str(), option.port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        sendto(sock, option.message.c_str(), option.message.size(), 0, (struct sockaddr*)&sock_storage, sizeof(sock_storage));

        // receive response from server
        int n = recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
        buffer[n] = '\0';  // null-terminate the received string
        _logger->writeln("received response: %s", buffer);
    }
    __finally2 {
        close_socket(sock, true, 0);

#if defined _WIN32 || defined _WIN64
        winsock_cleanup();
#endif
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new cmdline_t<OPTION>);
    *_cmdline << cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
              << cmdarg_t<OPTION>("-a", "address (127.0.0.1)", [](OPTION& o, char* param) -> void { o.address = param; }).optional().preced()
              << cmdarg_t<OPTION>("-p", "port (9000)", [](OPTION& o, char* param) -> void { o.port = atoi(param); }).optional().preced()
              << cmdarg_t<OPTION>("-m", "message", [](OPTION& o, char* param) -> void { o.message = param; }).optional().preced();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    client();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
