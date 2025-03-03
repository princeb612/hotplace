/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/io/system/socket.hpp>
#include <sdk/net/basic/tls/sdk.hpp>

namespace hotplace {
namespace net {

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
            ret = errorcode_t::different_type;
            __leave2;
        }

        bio_addr = BIO_ADDR_new();
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
