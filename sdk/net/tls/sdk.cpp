/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto.hpp>
#include <sdk/io/system/socket.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
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
             * 1) SSL_connect block issue, make SSL_connect non-blocking
             * 2) SSL_connect crash
             *    ; X509_LOOKUP_by_subject 에서 발생
             *      X509_LOOKUP *lu; // uninitialized
             *      lu=sk_X509_LOOKUP_value(ctx->get_cert_methods,i); // if sk_X509_LOOKUP_value fails
             *      j=X509_LOOKUP_by_subject(lu,type,name,&stmp); // crash
             */
            try {
                int ret_connect = 0;
                while (true) {
                    ret_connect = SSL_connect(ssl);
                    if (ret_connect == 0) {
                        ret = errorcode_t::internal_error;
                    } else if (ret_connect < 0) {
                        get_opensslerror(ret_connect);
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

return_t BIO_ADDR_to_sockaddr(BIO_ADDR* bio_addr, struct sockaddr* sockaddr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        size_t socklen4 = sizeof(struct sockaddr_in);
        size_t socklen6 = sizeof(struct sockaddr_in6);

        if ((nullptr == bio_addr) || (nullptr == sockaddr) || (addrlen < socklen4)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        memset(sockaddr, 0, addrlen);

        auto family = BIO_ADDR_family(bio_addr);
        struct sockaddr_in* addr4 = (struct sockaddr_in*)sockaddr;
        addr4->sin_family = family;
        switch (family) {
            case AF_INET: {
                BIO_ADDR_rawaddress(bio_addr, &addr4->sin_addr, nullptr);
                addr4->sin_port = BIO_ADDR_rawport(bio_addr);
            } break;
            case AF_INET6:
                if (addrlen >= socklen6) {
                    struct sockaddr_in6* addr6 = (struct sockaddr_in6*)sockaddr;
                    BIO_ADDR_rawaddress(bio_addr, &addr6->sin6_addr, nullptr);
                    addr6->sin6_port = BIO_ADDR_rawport(bio_addr);
                } else {
                    ret = errorcode_t::insufficient_buffer;
                }
                break;
            default:
                ret = errorcode_t::unknown;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t SSL_dgram_peer_sockaddr(SSL* ssl, struct sockaddr* sockaddr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    BIO_ADDR* bio_addr = nullptr;
    __try2 {
        if ((nullptr == ssl) || (nullptr == sockaddr)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int socktype = 0;
        socket_t sock = SSL_get_fd(ssl);
        typeof_socket(sock, socktype);
        if (SOCK_DGRAM != socktype) {
            ret = errorcode_t::difference_type;
            __leave2;
        }

        BIO_dgram_get_peer(SSL_get_rbio(ssl), bio_addr);
        BIO_ADDR_to_sockaddr(bio_addr, sockaddr, addrlen);
    }
    __finally2 {
        if (bio_addr) {
            BIO_ADDR_free(bio_addr);
        }
    }
    return ret;
}

return_t generate_cookie_sockaddr(binary_t& cookie, const sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        unsigned cookie_size = 16;
        binary_t key;
        advisor->get_cookie_secret(0, cookie_size, key);

        openssl_hash hash;
        hash_context_t* handle = nullptr;
        hash.open(&handle, "sha256", &key[0], key.size());
        hash.init(handle);
        hash.update(handle, (byte_t*)addr, addrlen);
        hash.finalize(handle, cookie);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_cookie_dgram_peer_sockaddr(binary_t& cookie, SSL* ssl) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ssl) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        sockaddr_storage_t addr;
        ret = SSL_dgram_peer_sockaddr(ssl, (sockaddr*)&addr, (socklen_t)sizeof(addr));
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = generate_cookie_sockaddr(cookie, (sockaddr*)&addr, (socklen_t)sizeof(addr));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
