/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @remarks
 *      references
 *      RFC 4346 The Transport Layer Security (TLS) Protocol Version 1.1
 *      RFC 4347 Datagram Transport Layer Security
 *      RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *      RFC 6347 Datagram Transport Layer Security Version 1.2
 *      RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *      RFC 8448 Example Handshake Traces for TLS 1.3
 *      RFC 8740 Using TLS 1.3 with HTTP/2
 *      RFC 9147 The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/io/system/socket.hpp>
#include <sdk/net/basic/openssl/openssl_tls.hpp>
#include <sdk/net/basic/openssl/openssl_tls_context.hpp>
#include <sdk/net/basic/openssl/sdk.hpp>
#include <sdk/net/basic/openssl/types.hpp>

namespace hotplace {
namespace net {

// #define TLS_CONTEXT_SIGNATURE 0x20120119

openssl_tls::openssl_tls(SSL_CTX* ctx) : _ctx(ctx) {
    if (nullptr == ctx) {
        throw exception(errorcode_t::not_specified);
    }
    SSL_CTX_up_ref(ctx);
    _shared.make_share(this);
}

openssl_tls::openssl_tls(openssl_tls_context* cert) : _ctx(nullptr) {
    if (cert) {
        _ctx = cert->get_ctx();
    }
    if (nullptr == _ctx) {
        throw exception(errorcode_t::not_specified);
    }
    SSL_CTX_up_ref(_ctx);
    _shared.make_share(this);
}

openssl_tls::~openssl_tls() { SSL_CTX_free(_ctx); }

int openssl_tls::addref() { return _shared.addref(); }

int openssl_tls::release() { return _shared.delref(); }

return_t openssl_tls::tls_open(socket_context_t** handle, socket_t fd, uint32 flags) {
    return_t ret = errorcode_t::success;
    socket_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle || INVALID_SOCKET == fd) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new socket_context_t, ret, __leave2);

        auto ssl = SSL_new(_ctx);
        if (nullptr == ssl) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        SSL_set_fd(ssl, (int)fd);

        context->fd = fd;
        context->handle.ssl = ssl;
        context->flags = flags | tls_using_openssl;

        if (flags & socket_context_flag_t::tls_nbio) {
            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
            set_sock_nbio(fd, 1);
        }

#if defined DEBUG
        if (istraceable(trace_category_crypto, loglevel_debug)) {
            basic_stream dbs;
            dbs.println("- SSL_new %p", ssl);
            trace_debug_event(trace_category_crypto, trace_event_openssl_info, &dbs);
        }
#endif

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            close(context);
        }
    }
    return ret;
}

return_t openssl_tls::dtls_open(socket_context_t** handle, socket_t fd, uint32 flags) {
    return_t ret = errorcode_t::success;
    socket_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nullptr == _ctx) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        __try_new_catch(context, new socket_context_t, ret, __leave2);

        /* SSL_accept */
        auto ssl = SSL_new(_ctx);
        SSL_set_fd(ssl, (int)fd);

        /* compose the context */
        context->fd = fd;
        context->handle.ssl = ssl;
        context->flags = flags | tls_using_openssl;

        if (flags & socket_context_flag_t::tls_nbio) {
            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
            set_sock_nbio(fd, 1);
        }

#if defined DEBUG
        if (istraceable(trace_category_crypto, loglevel_debug)) {
            basic_stream dbs;
            dbs.println("- SSL_new %p", ssl);
            trace_debug_event(trace_category_crypto, trace_event_openssl_info, &dbs);
        }
#endif

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            close(context);
        }
    }

    return ret;
}

return_t openssl_tls::close(socket_context_t* handle) {
    return_t ret = errorcode_t::success;
    socket_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        delete handle;
    }
    __finally2 {}
    return ret;
}

return_t openssl_tls::connect(socket_context_t** handle, int type, const char* address, uint16 port, uint32 wto) {
    return_t ret = errorcode_t::success;
    socket_t fd = INVALID_SOCKET;
    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    socket_context_t* context = nullptr;
    sockaddr_storage_t addr;
    uint32 flags = socket_context_flag_t::closesocket_ondestroy | socket_context_flag_t::tls_nbio;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = create_socket(&fd, &addr, type, address, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = connect_socket_addr(fd, (sockaddr*)&addr, sizeof(addr), wto);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = tls_open(&context, fd, flags);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_connect(context, wto);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = set_tls_io(context, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            close(context);
        }
    }
    return ret;
}

return_t openssl_tls::connectto(socket_context_t** handle, socket_t fd, const char* address, uint16 port, uint32 wto) {
    return_t ret = errorcode_t::success;
    sockaddr_storage_t addr = {
        0,
    };

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = addr_to_sockaddr(&addr, address, port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = connectto(handle, fd, (sockaddr*)&addr, sizeof(addr), wto);
    }
    __finally2 {}
    return ret;
}

return_t openssl_tls::connectto(socket_context_t** handle, socket_t fd, const sockaddr* addr, socklen_t addrlen, uint32 wto) {
    return_t ret = errorcode_t::success;
    socket_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = connect_socket_addr(fd, addr, addrlen, wto);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        uint32 mode = 0;
        ret = dtls_open(&context, fd, mode);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_connect(context, wto);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = set_tls_io(context, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            close(context);
        }
    }
    return ret;
}

return_t openssl_tls::tls_handshake(socket_context_t** handle, socket_t fd) {
    return_t ret = errorcode_t::success;
    socket_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nullptr == _ctx) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /**
         * blocking         passed
         * non-blocking     passed
         */

        int flags = socket_context_flag_t::closesocket_ondestroy | socket_context_flag_t::tls_nbio;
        ret = tls_open(&context, fd, flags);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_accept(context);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = set_tls_io(context, 0);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            close(context);
        }
    }
    return ret;
}

return_t openssl_tls::dtls_handshake(socket_context_t* handle, sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /**
         * blocking         passed
         * non-blocking     not yet
         */

        auto ssl = handle->handle.ssl;
        if (1 == SSL_is_init_finished(ssl)) {
            __leave2;
        }

        set_tls_io(handle, 1);

        /**
         *  SSL_get_state(ssl) -> TLS_ST_BEFORE
         *  DTLSv1_listen
         *  SSL_get_state(ssl) -> TLS_ST_SR_CLNT_HELLO
         *  SSL_accept
         *  SSL_get_state(ssl) -> TLS_ST_OK
         */

        ret = do_dtls_listen(handle, addr, addrlen);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_accept(handle);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}

    return ret;
}

return_t openssl_tls::do_connect(socket_context_t* handle, uint32 wto) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto ssl = handle->handle.ssl;
        auto fd = handle->fd;
        auto nbio = (handle->flags & tls_nbio) ? 1 : 0;
        int rc = 1;
        int flags = 0;

        if (0 == nbio) {
            set_sock_nbio(fd, 1);
        }

        try {
            /**
             *  TLS_ST_CW_CLNT_HELLO 0x0c
             *  TLS_ST_CR_SRVR_HELLO 0x03
             *  TLS_ST_CW_FINISHED   0x12
             *  TLS_ST_OK            0x01
             */
            do {
                flags = 0;
                rc = SSL_connect(ssl);
                if (rc < 1) {
                    int condition = SSL_get_error(ssl, rc);
                    switch (condition) {
                        case SSL_ERROR_WANT_WRITE:
                            flags |= SOCK_WAIT_WRITABLE;
                            break;
                        case SSL_ERROR_WANT_READ:
                            flags |= SOCK_WAIT_READABLE;
                            break;
                        default:
                            break;
                    }
                    if (flags) {
                        auto res = wait_socket(fd, wto * 1000, flags);
                        if (errorcode_t::success != res) {
                            flags = 0;
                        }
                    }
                }
            } while (flags && (1 != SSL_is_init_finished(ssl)));
        } catch (...) {
            /*
             * openssl-1.0.1i SSL_connect crash
             *    at X509_LOOKUP_by_subject
             *      X509_LOOKUP *lu; // uninitialized
             *      lu=sk_X509_LOOKUP_value(ctx->get_cert_methods,i); // if sk_X509_LOOKUP_value fails
             *      j=X509_LOOKUP_by_subject(lu,type,name,&stmp); // crash
             */
            ret = errorcode_t::unexpected;
        }

        if (0 == nbio) {
            set_sock_nbio(fd, 0);
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (1 != SSL_is_init_finished(ssl)) {
            if (0 == rc) {
                ret = errorcode_t::disconnect;
            } else {
                ret = errorcode_t::error_connect;
            }
        }
    }
    __finally2 {}

    return ret;
}

return_t openssl_tls::do_dtls_listen(socket_context_t* handle, sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    BIO_ADDR* bio_addr = nullptr;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto fd = handle->fd;
        auto ssl = handle->handle.ssl;
        int rc = 1;
        int flags = 0;

        if (1 == SSL_is_init_finished(ssl)) {
            __leave2;
        }

        bio_addr = BIO_ADDR_new();

        do {
            flags = 0;
            rc = DTLSv1_listen(ssl, bio_addr);
            //  0 HelloRetryRequest
            // -1 failure
            if (rc <= 1) {
                int condition = SSL_get_error(ssl, rc);
                switch (condition) {
                    case SSL_ERROR_WANT_WRITE:
                        flags |= SOCK_WAIT_WRITABLE;
                        break;
                    case SSL_ERROR_WANT_READ:
                        flags |= SOCK_WAIT_READABLE;
                        break;
                    default:
                        break;
                }
                if (flags) {
                    auto res = wait_socket(fd, 1 * 1000, flags);
                    if (errorcode_t::success != res) {
                        flags = 0;
                    }
                }
            }
        } while (flags);

        if (rc > 0) {
            if (addr) {
                BIO_ADDR_to_sockaddr(bio_addr, addr, addrlen);
            }
        } else {
            ret = get_opensslerror(rc);
        }
    }
    __finally2 {
        if (bio_addr) {
            BIO_ADDR_free(bio_addr);
        }
    }
    return ret;
}

return_t openssl_tls::do_accept(socket_context_t* handle) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto fd = handle->fd;
        auto ssl = handle->handle.ssl;
        auto tlsflags = handle->flags;
        int rc = 1;
        int flags = 0;

        if (1 == SSL_is_init_finished(ssl)) {
            __leave2;
        }

        __try2 {
            if (0 == (tlsflags & tls_nbio)) {
                set_sock_nbio(fd, 1);
            }

            /**
             *  TLS_ST_BEFORE        0x00
             *  TLS_ST_SR_CLNT_HELLO 0x14
             *  TLS_ST_OK            0x01
             */

            do {
                flags = 0;
                rc = SSL_accept(ssl);
                if (rc < 1) {
                    int condition = SSL_get_error(ssl, rc);
                    switch (condition) {
                        case SSL_ERROR_WANT_WRITE:
                            flags |= SOCK_WAIT_WRITABLE;
                            break;
                        case SSL_ERROR_WANT_READ:
                            flags |= SOCK_WAIT_READABLE;
                            break;
                        default:
                            break;
                    }
                    if (flags) {
                        auto res = wait_socket(fd, 1 * 1000, flags);
                        if (errorcode_t::success != res) {
                            flags = 0;
                        }
                    }
                }
            } while (flags && (1 != SSL_is_init_finished(ssl)));
        }
        __finally2 {
            if (1 != SSL_is_init_finished(ssl)) {
                if (0 == rc) {
                    ret = errorcode_t::disconnect;
                } else {
                    ret = errorcode_t::error_handshake;
                }
            }
            if (0 == (tlsflags & tls_nbio)) {
                set_sock_nbio(fd, 0);
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_tls::set_tls_io(socket_context_t* handle, int type) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto fd = handle->fd;
        auto ssl = handle->handle.ssl;
        auto rbio = SSL_get_rbio(ssl);

        /**
         *  SSL_set_bio - BIO_s_mem for TCP, BIO_s_datagram for UDP
         *
         *  test
         *
         *  openssl_tls_server_socket   BIO_s_mem       passed
         *  openssl_tls_client_socket   BIO_s_mem       passed
         *  openssl_dtls_server_socket  BIO_s_datagram  passed
         *  openssl_dtls_client_socket  BIO_s_datagram  not yet
         *                      BIO_s_mem       passed
         */
        if (0 == type) {
            auto sbio_read = BIO_new(BIO_s_mem());
            auto sbio_write = BIO_new(BIO_s_mem());
            SSL_set_bio(ssl, sbio_read, sbio_write);
        } else if (1 == type) {
            auto sbio = BIO_new_dgram(fd, BIO_NOCLOSE);
            SSL_set_bio(ssl, sbio, sbio);
            SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_tls::read(socket_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* cbread) {
    return_t ret = errorcode_t::success;
    int rc = 0;

    __try2 {
        if (nullptr == handle || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nullptr != cbread) {
            *cbread = 0;
        }

        size_t size_read = buffer_size;
        if (tls_io_flag_t::read_socket_recv & mode) {
            rc = ::recv(handle->fd, (char*)buffer, buffer_size, 0);
            if (0 == rc) { /* gracefully closed */
                ret = errorcode_t::disconnect;
                __leave2;
            }
            if (-1 == rc) {
                ret = get_lasterror(rc);
                __leave2;
            }

            size_read = rc;
            if (nullptr != cbread) {
                *cbread = rc;
            }
        }

        auto ssl = handle->handle.ssl;
        auto rbio = SSL_get_rbio(ssl);

        if (tls_io_flag_t::read_bio_write & mode) {
            BIO_write(rbio, buffer, (int)size_read);
        }

        if (tls_io_flag_t::read_ssl_read & mode) {
            int written = BIO_number_written(rbio);
            /**
             *  SSL_read
             *      ~ TLS 1.2   re-handshake
             *      TLS 1.3 ~   no re-handshake
             */
            rc = SSL_read(ssl, buffer, (int)buffer_size);
            if (rc <= 0) {
                int condition = SSL_get_error(ssl, rc);
                if (SSL_ERROR_WANT_READ == condition || SSL_ERROR_WANT_WRITE == condition) {
                    ret = errorcode_t::pending;
                } else if (SSL_ERROR_ZERO_RETURN == condition) {
                    auto rcs = SSL_shutdown(ssl);
                    if (2 == rcs) {
                        // The shutdown is not yet finished
                        SSL_shutdown(ssl);
                    }
                    ret = errorcode_t::disconnect;
                } else if (SSL_ERROR_NONE == condition) {
                    // do nothing
                } else {
                    ret = errorcode_t::internal_error;
                }
                __leave2;
            } else {
                if (buffer_size < (size_t)written) {
                    ret = errorcode_t::more_data;
                }
                if (nullptr != cbread) {
                    *cbread = rc;
                }
            }
        }
    }
    __finally2 {}

    return ret;
}

return_t openssl_tls::recvfrom(socket_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* cbread, struct sockaddr* addr,
                               socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    int rc = 0;

    __try2 {
        if (nullptr == handle || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (nullptr != cbread) {
            *cbread = 0;
        }

        size_t size_read = buffer_size;

        if (tls_io_flag_t::read_socket_recv & mode) {
            int flag = 0;
            if (tls_io_flag_t::peek_msg & mode) {
                flag = MSG_PEEK;
            }
            rc = ::recvfrom(handle->fd, (char*)buffer, buffer_size, flag, addr, addrlen);
            if (0 == rc) { /* gracefully closed */
                ret = errorcode_t::disconnect;
                __leave2;
            }
            if (-1 == rc) {
                ret = get_lasterror(rc);
                __leave2;
            }

            size_read = rc;
            if (nullptr != cbread) {
                *cbread = rc;
            }
        }

        auto ssl = handle->handle.ssl;
        auto rbio = SSL_get_rbio(ssl);

        if (tls_io_flag_t::read_bio_write & mode) {
            BIO_write(rbio, buffer, (int)size_read);
        }

        if (tls_io_flag_t::read_ssl_read & mode) {
            rc = SSL_read(ssl, buffer, (int)buffer_size);
            int condition = SSL_get_error(ssl, rc);
            if (rc <= 0) {
                if (SSL_ERROR_WANT_READ == condition || SSL_ERROR_WANT_WRITE == condition) {
                    ret = errorcode_t::pending;
                } else if (SSL_ERROR_ZERO_RETURN == condition) {
                    auto rcs = SSL_shutdown(ssl);
                    if (2 == rcs) {
                        // The shutdown is not yet finished
                        SSL_shutdown(ssl);
                    }
                    ret = errorcode_t::disconnect;
                } else if (SSL_ERROR_NONE == condition) {
                    // do nothing
                } else {
                    ret = errorcode_t::internal_error;
                }
            } else {
                if (nullptr != cbread) {
                    *cbread = rc;
                }
            }
        }
    }
    __finally2 {}

    return ret;
}

return_t openssl_tls::send(socket_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (size_sent) {
            *size_sent = 0;
        }

        auto ssl = handle->handle.ssl;
        auto wbio = SSL_get_wbio(ssl);

        if (tls_io_flag_t::send_ssl_write & mode) {
            int ret_write = SSL_write(ssl, data, (int)size_data);

            if (ret_write < 1) {
                ret = get_opensslerror(ret_write);
                __leave2;
            }
            if (size_sent) {
                *size_sent = ret_write;
            }
        }

        if (tls_io_flag_t::send_bio_read & mode) {
            int written = BIO_number_written(wbio);

            int ret_read = 0;
            std::vector<char> buf;
            buf.resize(written);

            ret_read = BIO_read(wbio, &buf[0], buf.size());
            if (ret_read < 1) {
                ret = get_opensslerror(ret_read);
                __leave2; /* too many traces here */
            }

            if (tls_io_flag_t::send_socket_send & mode) {
                ::send(handle->fd, &buf[0], ret_read, 0);
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_tls::sendto(socket_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent, const struct sockaddr* addr,
                             socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (size_sent) {
            *size_sent = 0;
        }

        auto ssl = handle->handle.ssl;
        auto wbio = SSL_get_wbio(ssl);

        if (tls_io_flag_t::send_ssl_write & mode) {
            int ret_write = SSL_write(ssl, data, (int)size_data);

            if (ret_write < 1) {
                ret = get_opensslerror(ret_write);
                __leave2;
            }
            if (size_sent) {
                *size_sent = ret_write;
            }
        }

        if (tls_io_flag_t::send_bio_read & mode) {
            int written = BIO_number_written(wbio);

            int ret_read = 0;
            std::vector<char> buf;
            buf.resize(written);

            ret_read = BIO_read(wbio, &buf[0], buf.size());
            if (ret_read < 1) {
                ret = get_opensslerror(ret_read);
                __leave2; /* too many traces here */
            }

            if (tls_io_flag_t::send_socket_send & mode) {
                ::sendto(handle->fd, &buf[0], ret_read, 0, addr, addrlen);
            }
        }
    }
    __finally2 {}
    return ret;
}

socket_t openssl_tls::get_socket(socket_context_t* handle) {
    socket_t fd = INVALID_SOCKET;

    if (nullptr != handle) {
        fd = handle->fd;
    }
    return fd;
}

SSL_CTX* openssl_tls::get() { return _ctx; }

}  // namespace net
}  // namespace hotplace
