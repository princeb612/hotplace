/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/net/basic/sdk.hpp>

namespace hotplace {
namespace net {

return_t tls_connect(socket_t sock, SSL* ssl, uint32 dwSeconds, uint32 nbio) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == ssl) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == nbio) { /* blocking */
            int nRet = 0;
            nRet = SSL_connect(ssl);

            if (nRet <= 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
        } else { /* non-blocking */
            set_sock_nbio(sock, 1);

            /*
             * openssl-1.0.1i
             * 1) blocking io 방식에서 SSL_connect 멈추는 현상 발생
             *    -> non-blocking io 방식으로 변경
             * 2) SSL_connect crash
             *    ; X509_LOOKUP_by_subject 에서 발생
             *      X509_LOOKUP *lu; // 초기화되지 않음
             *      lu=sk_X509_LOOKUP_value(ctx->get_cert_methods,i); // sk_X509_LOOKUP_value 실패시 잘못된 주소 공간
             *      j=X509_LOOKUP_by_subject(lu,type,name,&stmp); // crash 발생
             */
            try {
                int ret_connect = 0;
                while (true) {
                    ret_connect = SSL_connect(ssl);
                    if (ret_connect == 0) {
                        ret = errorcode_t::internal_error;
                    } else if (ret_connect < 0) {
                        switch (SSL_get_error(ssl, ret_connect)) {
                            case SSL_ERROR_WANT_READ:
                                if (errorcode_t::success == wait_socket(sock, dwSeconds * 1000, SOCK_WAIT_READABLE)) {
                                    continue;
                                }
                                ret = errorcode_t::internal_error;
                                break;

                            case SSL_ERROR_WANT_WRITE:
                                if (errorcode_t::success == wait_socket(sock, dwSeconds * 1000, SOCK_WAIT_WRITABLE)) {
                                    continue;
                                }
                                continue;

                            default:
                                ret = errorcode_t::internal_error;
                                break;
                        }
                    }
                    break;
                }
            } catch (...) {
                ret = errorcode_t::internal_error;
            }

            set_sock_nbio(sock, 0);

            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace net
}  // namespace hotplace
