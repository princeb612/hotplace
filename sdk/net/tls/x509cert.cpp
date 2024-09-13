/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/binary.hpp>
#include <sdk/crypto.hpp>
#include <sdk/io.hpp>
#include <sdk/net/tls/sdk.hpp>
#include <sdk/net/tls/x509cert.hpp>
#include <sdk/nostd.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

static void set_info_callback_routine(const SSL* ssl, int where, int ret) {
    basic_stream bs;
    valist va;
    const char* state = "undef";
    if (where & SSL_CB_LOOP) {
        if (where & SSL_ST_CONNECT) {
            state = "connect";
        } else if (where & SSL_ST_ACCEPT) {
            state = "accept";
        }
        va << "loop" << state << SSL_state_string_long(ssl) << SSL_get_cipher_name(ssl);
    } else if (where & SSL_CB_EXIT) {
        if (where & SSL_ST_CONNECT) {
            state = "connect";
        } else if (where & SSL_ST_ACCEPT) {
            state = "accept";
        }
        va << "exit" << state << SSL_state_string_long(ssl);
    } else if (where & SSL_CB_ALERT) {
        if (where & SSL_CB_READ) {
            state = "read";
        } else if (where & SSL_CB_WRITE) {
            state = "write";
        }
        va << "alert" << state << SSL_alert_type_string_long(ret) << SSL_alert_desc_string_long(ret);
    } else if (where & SSL_CB_HANDSHAKE_START) {
        if (where & SSL_CB_READ) {
            state = "read";
        } else if (where & SSL_CB_WRITE) {
            state = "write";
        }
        va << "handshake start" << state << SSL_alert_type_string_long(ret) << SSL_alert_desc_string_long(ret);
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
        if (where & SSL_CB_READ) {
            state = "read";
        } else if (where & SSL_CB_WRITE) {
            state = "write";
        }
        va << "handshake done" << state << SSL_alert_type_string_long(ret) << SSL_alert_desc_string_long(ret);
    } else {
        va << "state" << SSL_state_string_long(ssl) << SSL_alert_type_string_long(ret) << SSL_alert_desc_string_long(ret);
    }

    // # define TLS1_3_VERSION  0x0304
    // # define TLS1_VERSION    0x0301
    // # define TLS1_1_VERSION  0x0302
    // # define TLS1_2_VERSION  0x0303
    // # define DTLS1_VERSION   0xFEFF
    // # define DTLS1_2_VERSION 0xFEFD

    bs.printf("SSL %08x ", SSL_version(ssl));
    switch (va.size()) {
        case 3:
            sprintf(&bs, "{1} {2}:{3}", va);
            break;
        case 4:
            sprintf(&bs, "{1} {2}:{3}:{4}", va);
            break;
        default:
            break;
    }
    std::cout << bs << std::endl;
    fflush(stdout);
}

static int set_cookie_generate_callback_routine(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len) {
    binary_t bin;
    dtls_cookie_dgram_peer_sockaddr(bin, ssl);

    memcpy(cookie, &bin[0], bin.size());
    *cookie_len = bin.size();

    return 1;
}

static int set_cookie_verify_callback_routine(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len) {
    int ret = 0;

    binary_t bin;
    dtls_cookie_dgram_peer_sockaddr(bin, ssl);

    binary_t bin_cookie;
    binary_append(bin_cookie, cookie, cookie_len);
    if (bin_cookie == bin) {
        ret = 1;
    }

    return ret;
}

return_t x509cert_open_simple(uint32 flag, SSL_CTX** context) {
    return_t ret = errorcode_t::success;
    SSL_CTX* ssl_ctx = nullptr;

    __try2 {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const SSL_METHOD* method = nullptr;
        if (x509cert_flag_tls == flag) {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
            method = TLS_method();
#else
            method = SSLv23_method();
#endif
        } else if (x509cert_flag_dtls == flag) {
            method = DTLS_method();
        } else {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ssl_ctx = SSL_CTX_new(method);
        if (nullptr == ssl_ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        long option_flags = 0;

        /* 1.0.x defines SSL_OP_NO_SSLv2~SSL_OP_NO_TLSv1_1 */
#ifndef SSL_OP_NO_TLSv1_2
#define SSL_OP_NO_TLSv1_2 0x0
#endif
#ifndef SSL_OP_NO_DTLSv1
#define SSL_OP_NO_DTLSv1 0x0
#endif
#ifndef SSL_OP_NO_DTLSv1_2
#define SSL_OP_NO_DTLSv1_2 0x0
#endif

        if (x509cert_flag_tls == flag) {
            /*
             * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
             * RFC 8996 Deprecating TLS 1.0 and TLS 1.1
             */
            SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
            option_flags = (SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1); /* TLS 1.2 and above */
        } else if (x509cert_flag_dtls == flag) {
            SSL_CTX_set_min_proto_version(ssl_ctx, DTLS1_2_VERSION);
            SSL_CTX_set_cookie_generate_cb(ssl_ctx, set_cookie_generate_callback_routine);
            SSL_CTX_set_cookie_verify_cb(ssl_ctx, set_cookie_verify_callback_routine);

            option_flags = SSL_OP_NO_DTLSv1;
        }
        SSL_CTX_set_options(ssl_ctx, option_flags);
        SSL_CTX_set_verify(ssl_ctx, 0, nullptr);

        uint32 option = get_trace_option();
        if (trace_option_t::trace_bt & option) {
            SSL_CTX_set_info_callback(ssl_ctx, set_info_callback_routine);
        }

        *context = ssl_ctx;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

static int set_default_passwd_callback_routine(char* buf, int num, int rwflag, void* userdata) {
    stream_t* stream = (stream_t*)userdata;
    size_t len = stream->size();

    strncpy(buf, (char*)stream->data(), len);
    return len;
}

return_t x509cert_open(uint32 flag, SSL_CTX** context, const char* cert_file, const char* key_file, const char* password, const char* chain_file,
                       const char* cacert_file) {
    return_t ret = errorcode_t::success;
    SSL_CTX* ssl_ctx = nullptr;
    SSL* ssl = nullptr;

    __try2 {
        if (nullptr == context || nullptr == key_file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = x509cert_open_simple(flag, &ssl_ctx);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        basic_stream bs;
        if (password) {
            bs.printf(password);
        }

        SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, &bs);
        SSL_CTX_set_default_passwd_cb(ssl_ctx, set_default_passwd_callback_routine);

        int check = 0;
        // certificate
        if (cert_file) {
            check = SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM);
            ret = get_opensslerror(check);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
        // private key
        {
            check = SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM);
            ret = get_opensslerror(check);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            check = SSL_CTX_check_private_key(ssl_ctx);
            ret = get_opensslerror(check);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
        // certificate chain
        if (chain_file) {
            check = SSL_CTX_use_certificate_chain_file(ssl_ctx, chain_file);
            ret = get_opensslerror(check);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
        // CA certificate
        if (cacert_file) {
            check = SSL_CTX_load_verify_locations(ssl_ctx, cacert_file, nullptr);
            ret = get_opensslerror(check);
            if (errorcode_t::success != ret) {
                __leave2;
            }
            {
                check = SSL_CTX_set_default_verify_file(ssl_ctx);
                ret = get_opensslerror(check);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
            }
        }

        //    ~   not_before  ~  not_after   ~
        // invalid          valid         invalid
        {
            ssl = SSL_new(ssl_ctx);
            if (nullptr == ssl) {
                ret = errorcode_t::internal_error_5;
                __leave2;
            }

            X509* x509 = SSL_get_certificate(ssl);
            if (nullptr == x509) {
                ret = errorcode_t::internal_error_6;
                __leave2;
            }

            // function         UTC/local?  in          out         return
            // ASN1_TIME_to_tm  UTC         ASN1_TIME*  tm*
            // time             local       N/A         time_t*     time_t
            // mktime           local       tm*         N/A         time_t
            // timegm/_mkgmtime UTC         tm*         N/A         time_t

            ASN1_TIME* asn1time_not_before = X509_get_notBefore(x509);
            ASN1_TIME* asn1time_not_after = X509_get_notAfter(x509);
            if (asn1time_not_before && asn1time_not_after) {
                struct tm tm_not_before;
                struct tm tm_not_after;
                // GMT(UTC)
                ASN1_TIME_to_tm(asn1time_not_before, &tm_not_before);
                ASN1_TIME_to_tm(asn1time_not_after, &tm_not_after);
                // localtime
                time_t now = time(nullptr);
                time_t not_before = mktime(&tm_not_before);
                time_t not_after = mktime(&tm_not_after);

                if ((not_before < now) && (now < not_after)) {
                    // do nothing
                } else {
                    ret = errorcode_t::expired;
                    // __leave2;
                }
            }
        }

        *context = ssl_ctx;
    }
    __finally2 {
        if (ssl) {
            SSL_free(ssl);
        }
        switch (ret) {
            case errorcode_t::success:
            case errorcode_t::expired:
                break;
            default:
                SSL_CTX_free(ssl_ctx);
                break;
        }
    }
    return ret;
}

x509cert::x509cert(uint32 flag) : _ctx(nullptr) { x509cert_open_simple(flag, &_ctx); }

x509cert::x509cert(uint32 flag, const char* cert_file, const char* key_file, const char* password, const char* chain_file, const char* cacert_file)
    : _ctx(nullptr) {
    x509cert_open(flag, &_ctx, cert_file, key_file, password, chain_file, cacert_file);
}

x509cert::~x509cert() {
    if (_ctx) {
        SSL_CTX_free(_ctx);
    }
}

x509cert& x509cert::set_cipher_list(const char* list) {
    if (list) {
        if (_ctx) {
            SSL_CTX_set_cipher_list(_ctx, list);
        }
    }
    return *this;
}

x509cert& x509cert::set_verify(int mode) {
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

x509cert& x509cert::enable_alpn_h2(bool enable) {
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

SSL_CTX* x509cert::get_ctx() { return _ctx; }

}  // namespace net
}  // namespace hotplace
