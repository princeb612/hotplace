/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base.hpp>
#include <sdk/crypto.hpp>
#include <sdk/io.hpp>
#include <sdk/net/tls/x509.hpp>

namespace hotplace {
using namespace io;
namespace net {

return_t x509_open_simple(SSL_CTX** context) {
    return_t ret = errorcode_t::success;
    SSL_CTX* ssl_ctx = nullptr;

    __try2 {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        const SSL_METHOD* method = TLS_method();
#else
        const SSL_METHOD* method = SSLv23_method();
#endif
        ssl_ctx = SSL_CTX_new(method);
        if (nullptr == ssl_ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        long option_flags = 0;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        /* 1.0.x defines SSL_OP_NO_SSLv2~SSL_OP_NO_TLSv1_1 */
#ifndef SSL_OP_NO_TLSv1_2
#define SSL_OP_NO_TLSv1_2 0x0
#endif
#endif
        /*
         * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
         * RFC 8996 Deprecating TLS 1.0 and TLS 1.1
         */
        option_flags = (SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1); /* TLS 1.2 and above */
        SSL_CTX_set_options(ssl_ctx, option_flags);
        SSL_CTX_set_verify(ssl_ctx, 0, nullptr);

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

return_t x509cert_open(SSL_CTX** context, const char* cert_file, const char* key_file, const char* password, const char* chain_file) {
    return_t ret = errorcode_t::success;
    SSL_CTX* ssl_ctx = nullptr;
    SSL* ssl = nullptr;

    __try2 {
        if (nullptr == context || nullptr == cert_file || nullptr == key_file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = x509_open_simple(&ssl_ctx);
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
        check = SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM);
        if (check < 0) {
            ret = errorcode_t::internal_error_1;
            __leave2;
        }

        check = SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM);
        if (check < 0) {
            ret = errorcode_t::internal_error_2;
            __leave2;
        }
        check = SSL_CTX_check_private_key(ssl_ctx);
        if (check < 0) {
            ret = errorcode_t::internal_error_3;
            __leave2;
        }

        if (chain_file) {
            check = SSL_CTX_use_certificate_chain_file(ssl_ctx, chain_file);
            if (check < 0) {
                ret = errorcode_t::internal_error_4;
                __leave2;
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

            ASN1_TIME* time_not_before = X509_get_notBefore(x509);
            ASN1_TIME* time_not_after = X509_get_notAfter(x509);
            if (time_not_before && time_not_after) {
                asn1time_t asn1_not_before(time_not_before->type, (char*)time_not_before->data);
                asn1time_t asn1_not_after(time_not_after->type, (char*)time_not_after->data);
                datetime now;
                datetime not_before(asn1_not_before);
                datetime not_after(asn1_not_after);

                if ((not_before < now) && (now < not_after)) {
                    // do nothing
                } else {
                    ret = errorcode_t::expired;
                    __leave2;
                }
            }
        }

        *context = ssl_ctx;
    }
    __finally2 {
        if (ssl) {
            SSL_free(ssl);
        }
        if (errorcode_t::success != ret) {
            SSL_CTX_free(ssl_ctx);
        }
    }
    return ret;
}

x509cert::x509cert() : _x509(nullptr) { x509_open_simple(&_x509); }

x509cert::x509cert(const char* cert_file, const char* key_file, const char* password, const char* chain_file) : _x509(nullptr) {
    x509cert_open(&_x509, cert_file, key_file, password, chain_file);
}

x509cert::~x509cert() {
    if (_x509) {
        SSL_CTX_free(_x509);
    }
}

x509cert& x509cert::set_cipher_list(const char* list) {
    if (list) {
        SSL_CTX_set_cipher_list(_x509, list);
    }
    return *this;
}

x509cert& x509cert::set_verify(int mode) {
    SSL_CTX_set_verify(_x509, mode, nullptr);
    return *this;
}

static int set_alpn_select_cb(SSL* ssl, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg) {
    int ret = SSL_TLSEXT_ERR_NOACK;

    // 00000000 : 02 68 32 08 68 74 74 70 2F 31 2E 31 -- -- -- -- | .h2.http/1.1

    int pos_h2 = -1;
    int pos_h1_1 = -1;

    for (int pos = 0; pos < inlen;) {
        uint8 len = in[pos];
        if (0 == strncmp((char*)in + pos, "\x2h2", 3)) {
            pos_h2 = pos;
        } else if (0 == strncmp((char*)in + pos, "\x8http/1.1", 9)) {
            pos_h1_1 = pos;
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

    return ret;
}

x509cert& x509cert::enable_alpn_h2(bool enable) {
    if (enable) {
        // RFC 7301 Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension
        // RFC 7540 3.1.  HTTP/2 Version Identification
        SSL_CTX_set_alpn_select_cb(_x509, set_alpn_select_cb, nullptr);
    } else {
        SSL_CTX_set_alpn_select_cb(_x509, nullptr, nullptr);
    }
    return *this;
}

SSL_CTX* x509cert::get() { return _x509; }

}  // namespace net
}  // namespace hotplace
