/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/pattern/aho_corasick.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls_context.hpp>
#include <hotplace/sdk/net/basic/openssl/sdk.hpp>
#include <hotplace/sdk/net/tls/sslkeylog_exporter.hpp>

namespace hotplace {
namespace net {

openssl_tls_context::openssl_tls_context(uint32 flag) : _ctx(nullptr) { tlscontext_open_simple(&_ctx, flag); }

openssl_tls_context::openssl_tls_context(uint32 flag, const char* cert_file, const char* key_file, const char* password, const char* chain_file)
    : _ctx(nullptr) {
    openssl_tls_context_open(&_ctx, flag, cert_file, key_file, password, chain_file);
}

openssl_tls_context::openssl_tls_context(const openssl_tls_context& rhs) : _ctx(rhs._ctx) {
    if (nullptr == _ctx) {
        throw exception(not_specified);
    }
    SSL_CTX_up_ref(_ctx);
}

openssl_tls_context::openssl_tls_context(openssl_tls_context&& rhs) : _ctx(std::move(rhs._ctx)) {
    if (nullptr == _ctx) {
        throw exception(not_specified);
    }
}

openssl_tls_context::openssl_tls_context(openssl_tls* tls) {
    if (tls && tls->get()) {
        _ctx = tls->get();
        SSL_CTX_up_ref(_ctx);
    } else {
        throw exception(not_specified);
    }
}

openssl_tls_context::openssl_tls_context(SSL_CTX* ctx) : _ctx(ctx) {
    if (nullptr == _ctx) {
        throw exception(not_specified);
    }
    SSL_CTX_up_ref(_ctx);
}

openssl_tls_context::~openssl_tls_context() {
    if (_ctx) {
        SSL_CTX_free(_ctx);
    }
}

openssl_tls_context& openssl_tls_context::set_cipher_list(const char* list) {
    if (list) {
        if (_ctx) {
            SSL_CTX_set_cipher_list(_ctx, list);
        }
    }
    return *this;
}

openssl_tls_context& openssl_tls_context::set_group_list(const char* list) {
    if (list) {
        if (_ctx) {
            // IMPORTANT check len
            auto len = strlen(list);
            if (len) {
                SSL_CTX_set1_groups_list(_ctx, list);
            }
        }
    }
    return *this;
}

openssl_tls_context& openssl_tls_context::set_use_dh(int bits) {
    return_t ret = errorcode_t::success;
    DH* dh = nullptr;
    int rc = 0;
    __try2 {
        if (nullptr == _ctx) {
            // ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto options = SSL_CTX_get_options(_ctx);

        dh = DH_new();
        if (nullptr == dh) {
            __leave2;
        }

        rc = DH_generate_parameters_ex(dh, bits, DH_GENERATOR_2, NULL);
        if (rc < 1) {
            ret = get_opensslerror(rc);
            __leave2;
        }

        // #   define DH_CHECK_P_NOT_PRIME            0x01
        // #   define DH_CHECK_P_NOT_SAFE_PRIME       0x02
        // #   define DH_UNABLE_TO_CHECK_GENERATOR    0x04
        // #   define DH_NOT_SUITABLE_GENERATOR       0x08
        // #   define DH_CHECK_Q_NOT_PRIME            0x10
        // #   define DH_CHECK_INVALID_Q_VALUE        0x20 /* +DH_check_pub_key */
        // #   define DH_CHECK_INVALID_J_VALUE        0x40
        // #   define DH_MODULUS_TOO_SMALL            0x80
        // #   define DH_MODULUS_TOO_LARGE            0x100 /* +DH_check_pub_key */

        int codes = 0;
        rc = DH_check(dh, &codes);
        if (rc < 1) {
            ret = get_opensslerror(rc);
            __leave2;
        }
        if (0 != codes) {
            // ret = errorcode_t::error_openssl_inside;
            __leave2;
        }

        SSL_CTX_set_options(_ctx, SSL_OP_SINGLE_DH_USE);
        SSL_CTX_set_tmp_dh(_ctx, dh);
    }
    __finally2 {
        if (dh) {
            DH_free(dh);
        }
    }
    return *this;
}

openssl_tls_context& openssl_tls_context::set_verify(int mode) {
    if (_ctx) {
        SSL_CTX_set_verify(_ctx, mode, nullptr);
    }
    return *this;
}

static int set_alpn_select_h2_cb(SSL* ssl, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg) {
    // TLS Application-Layer Protocol Negotiation Extension
    // see enable_alpn_h2, http_server_builder, test/httpserver2

    int ret = SSL_TLSEXT_ERR_NOACK;

    // 00000000 : 02 68 32 08 68 74 74 70 2F 31 2E 31 -- -- -- -- | .h2.http/1.1

#if 1
    int pos_h2 = -1;
    int pos_h1_1 = -1;

    for (int pos = 0; pos < inlen;) {
        uint8 len = in[pos];
        if (0 == strncmp((char*)in + pos, "\x2h2", 3)) {
            pos_h2 = pos;
            break;
        } else if (0 == strncmp((char*)in + pos, "\x8http/1.1", 9)) {
            pos_h1_1 = pos;
            // keep searching h2
        }
        pos += (len + 1);
    }

    if (pos_h2 != -1) {
        *out = in + pos_h2 + 1;
        *outlen = in[pos_h2];
        ret = SSL_TLSEXT_ERR_OK;
    } else if (pos_h1_1 != -1) {
        *out = in + pos_h1_1 + 1;
        *outlen = in[pos_h1_1];
        ret = SSL_TLSEXT_ERR_OK;
    }
#else
    // tested codes

    t_aho_corasick<char> ac;
    std::multimap<unsigned, range_t> rearranged;

    ac.insert("\x2h2", 3);        // pattern [0]
    ac.insert("\x8http/1.1", 9);  // pattern [1]
    ac.build();

    auto result = ac.search((char*)in, inlen);

    ac.order_by_pattern(result, rearranged);

    auto select = [&](unsigned pid) -> void {
        auto iter = rearranged.lower_bound(pid);  // pattern id
        if (rearranged.end() != iter) {
            range_t& range = iter->second;
            *out = in + range.begin + 1;  // h2, http1.1
            *outlen = in[range.begin];    // \x2, \8
            ret = SSL_TLSEXT_ERR_OK;
        }
    };

    select(0);  // \x2h2
    if (SSL_TLSEXT_ERR_OK != ret) {
        select(1);  // \x8http/1.1
    }
#endif

    return ret;
}

openssl_tls_context& openssl_tls_context::enable_alpn_h2(bool enable) {
    if (enable) {
        // RFC 7301 Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension
        // RFC 7540 3.1.  HTTP/2 Version Identification
        if (_ctx) {
            SSL_CTX_set_alpn_select_cb(_ctx, set_alpn_select_h2_cb, nullptr);
        }
    } else {
        if (_ctx) {
            SSL_CTX_set_alpn_select_cb(_ctx, nullptr, nullptr);
        }
    }
    return *this;
}

SSL_CTX* openssl_tls_context::get_ctx() { return _ctx; }

}  // namespace net
}  // namespace hotplace
