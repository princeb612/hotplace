/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#if defined _WIN32
#include <winsock2.h>
#include <windows.h>
#include <excpt.h>
#include <imagehlp.h>

#define PACKAGE "package"
#define PACKAGE_VERSION "0.1"

#include <bfd.h>
#include <psapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#endif

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <exception>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;

class simple_instance
{
public:
    simple_instance ()
    {
        std::cout << "constructor" << std::endl;
    }
    ~simple_instance ()
    {
        std::cout << "destructor" << std::endl;
    }
    void dosomething ()
    {
        std::cout << "hello world" << std::endl;
    }
};

void code_careful_shared_instance ()
{
    t_shared_instance <simple_instance> inst;

    inst.make_share (new simple_instance);

    try {
        // errorcode_t::already_assigned
        inst.make_share (nullptr);
    } catch (errorcode_t code) {
        printf ("errorcode_t %08x\n", code);
    }
}

void code_careful_tls ()
{
    transport_layer_security* tls = nullptr;

    try {
        // errorcode_t::invalid_context wo SSL_CTX*
        tls = new transport_layer_security (nullptr);
    } catch (errorcode_t code) {
        printf ("errorcode_t %08x\n", code);
    }
}

void code_careful_tls_client ()
{
    transport_layer_security_client* tls_client = nullptr;

    try {
        // errorcode_t::invalid_context wo transport_layer_security*
        tls_client = new transport_layer_security_client (nullptr);
    } catch (errorcode_t code) {
        printf ("errorcode_t %08x\n", code);
    }
}

void code_careful_tls_server ()
{
    transport_layer_security_server* tls_server = nullptr;

    try {
        // errorcode_t::invalid_context wo transport_layer_security*
        tls_server = new transport_layer_security_server (nullptr);
    } catch (errorcode_t code) {
        printf ("errorcode_t %08x\n", code);
    }
}

// Secure Programming Cookbook / Chap.12 Anti-Tempering / 12.8 Disguising Boolean Values
typedef struct _disguised_bool_t {
    int8 x;
    int8 y;
} disguised_bool_t;

#define INIT_DISGUISED_BOOL { 1, -1 }
#define SET_DISGUISED_BOOL_TRUE(b) do { b.x = 1, b.y = 0; } while (0)
#define SET_DISGUISED_BOOL_FALSE(b) do { b.x = 1, b.y = -1; } while (0)
#define TEST_DISGUISED_BOOL(b) (b.x + b.y)

disguised_bool_t bool_type = INIT_DISGUISED_BOOL;

int main ()
{
    code_careful_shared_instance ();
    code_careful_tls ();
    code_careful_tls_client ();
    code_careful_tls_server ();

    _test_case.report (5);
    return _test_case.result ();
}
