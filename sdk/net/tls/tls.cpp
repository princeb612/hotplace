/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/tls/tls.hpp>

namespace hotplace {
namespace net {

#define TLS_CONTEXT_SIGNATURE 0x20120119

enum TLS_CONTEXT_FLAG {
    TLS_CONTEXT_CLOSESOCKET_ONDESTROY = (1 << 0),
};

typedef struct _TLS_CONTEXT {
    uint32 _signature;
    uint32 _flags;
    socket_t _socket;
    SSL*     _ssl;
    BIO*     _sbio_read;
    BIO*     _sbio_write;
} TLS_CONTEXT;

transport_layer_security::transport_layer_security (SSL_CTX* x509) : _x509 (x509)
{
    if (nullptr == x509) {
        throw errorcode_t::invalid_context;
    }
    SSL_CTX_up_ref (x509);
    _shared.make_share (this);
}

transport_layer_security::~transport_layer_security ()
{
    SSL_CTX_free (_x509);
}

int transport_layer_security::addref ()
{
    return _shared.addref ();
}

int transport_layer_security::release ()
{
    return _shared.delref ();
}

return_t transport_layer_security::connect (tls_context_t** handle, int type, const char* address, uint16 port, uint32 timeout_connect)
{
    return_t ret = errorcode_t::success;
    socket_t sock = INVALID_SOCKET;
    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    TLS_CONTEXT* context = nullptr;
    sockaddr_storage_t sockaddr_address;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (nullptr == _x509) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }
        SSL_CTX* tls_ctx = _x509;

        __try_new_catch (context, new TLS_CONTEXT, ret, __leave2_trace (ret));

        memset (context, 0, sizeof (TLS_CONTEXT));
        memset (&sockaddr_address, 0, sizeof sockaddr_address);

        ret = create_socket (&sock, &sockaddr_address, SOCK_STREAM, address, port);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        ret = connect_socket_addr (sock, &sockaddr_address, sizeof (sockaddr_address), timeout_connect);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        ssl = SSL_new (tls_ctx);
        if (nullptr == ssl) {
            ret = errorcode_t::internal_error;
            __leave2_trace (ret);
        }
        SSL_set_fd (ssl, (int) sock);

        ret = tls_connect (sock, ssl, timeout_connect, 1);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        sbio_read = BIO_new (BIO_s_mem ());
        sbio_write = BIO_new (BIO_s_mem ());
        SSL_set_bio (ssl, sbio_read, sbio_write);
        //SSL_set_mode (ssl, SSL_MODE_AUTO_RETRY);

        context->_flags = TLS_CONTEXT_CLOSESOCKET_ONDESTROY;
        context->_socket = sock;
        context->_ssl = ssl;

        context->_sbio_read = sbio_read;
        context->_sbio_write = sbio_write;
        context->_signature = TLS_CONTEXT_SIGNATURE;

        *handle = context;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            close_socket (sock, true, 0);

            if (nullptr != ssl) {
                SSL_free (ssl);
            }
            if (nullptr != context) {
                context->_signature = 0;
                delete context;
            }
        }
    }
    return ret;
}

return_t transport_layer_security::connect (tls_context_t** handle, socket_t sock, uint32 timeout_seconds)
{
    return_t ret = errorcode_t::success;
    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    TLS_CONTEXT* context = nullptr;

    __try2
    {
        if (nullptr == handle || INVALID_SOCKET == sock) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (nullptr == _x509) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }
        SSL_CTX* tls_ctx = _x509;

        __try_new_catch (context, new TLS_CONTEXT, ret, __leave2_trace (ret));

        memset (context, 0, sizeof (TLS_CONTEXT));

        ssl = SSL_new (tls_ctx);
        if (nullptr == ssl) {
            ret = errorcode_t::internal_error;
            __leave2_trace (ret);
        }
        SSL_set_fd (ssl, (int) sock);

        ret = tls_connect (sock, ssl, timeout_seconds, 1);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }

        sbio_read = BIO_new (BIO_s_mem ());
        sbio_write = BIO_new (BIO_s_mem ());
        SSL_set_bio (ssl, sbio_read, sbio_write);

        context->_socket = sock;
        context->_ssl = ssl;

        context->_sbio_read = sbio_read;
        context->_sbio_write = sbio_write;
        context->_signature = TLS_CONTEXT_SIGNATURE;

        *handle = context;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            /* [in parameter] _socket 은 close 하지 않는다. */

            if (nullptr != ssl) {
                SSL_free (ssl);
            }
            if (nullptr != context) {
                context->_signature = 0;
                delete context;
            }
        }
    }
    return ret;
}

return_t transport_layer_security::accept (tls_context_t** handle, socket_t fd)
{
    return_t ret = errorcode_t::success;

    BIO* sbio_read = nullptr;
    BIO* sbio_write = nullptr;
    SSL* ssl = nullptr;
    TLS_CONTEXT* context = nullptr;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (nullptr == _x509) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }
        SSL_CTX* tls_ctx = _x509;

        __try_new_catch (context, new TLS_CONTEXT, ret, __leave2_trace (ret));

        memset (context, 0, sizeof (TLS_CONTEXT));

        /* SSL_accept */
        ssl = SSL_new (tls_ctx);
        SSL_set_fd (ssl, (int) fd);

        set_sock_nbio (fd, 1);

        fd_set rfdset;
        fd_set wfdset;

        int status = -1;
        do {
            FD_ZERO (&rfdset);
            FD_ZERO (&wfdset);

            status = SSL_accept (ssl);
            int condition = SSL_get_error (ssl, status);
            switch (condition) {
                case SSL_ERROR_NONE:
                    status = 0;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    FD_SET (fd, &wfdset);
                    status = 1;
                    break;
                case SSL_ERROR_WANT_READ:
                    FD_SET (fd, &rfdset);
                    status = 1;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                case SSL_ERROR_SYSCALL:
                    // peer closed connection during SSL handshake
                    status = -1;
                    break;
                default:
                    status = -1;
                    break;
            }
            if (1 == status) {
                struct timeval tv;
                tv.tv_sec = 2;
                tv.tv_usec = 0;

                status = select (fd + 1, &rfdset, &wfdset, nullptr, &tv);
                // 0 timeout
                // -1 error
                if (status >= 1) {
                    status = 1;
                } else {
                    status = -1;
                }
            }
        } while ((1 == status) && !SSL_is_init_finished (ssl));

        set_sock_nbio (fd, 0);

        if (status < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        /* SSL_set_bio */
        sbio_read = BIO_new (BIO_s_mem ());
        sbio_write = BIO_new (BIO_s_mem ());
        SSL_set_bio (ssl, sbio_read, sbio_write);

        /* compose the context */
        context->_socket = fd;
        context->_ssl = ssl;

        context->_sbio_read = sbio_read;
        context->_sbio_write = sbio_write;
        context->_signature = TLS_CONTEXT_SIGNATURE;

        *handle = context;
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (INVALID_SOCKET != fd) {
#if defined __linux__ || defined __APPLE__
                ::close (fd);
#elif defined _WIN32 || defined _WIN64
                closesocket (fd);
#endif
            }
            if (nullptr != ssl) {
                //SSL_shutdown(ssl);
                SSL_free (ssl);
            }
            if (nullptr != context) {
                context->_signature = 0;
                delete context;
            }
        }
    }

    return ret;
}

return_t transport_layer_security::close (tls_context_t* handle)
{
    return_t ret = errorcode_t::success;
    TLS_CONTEXT* context = nullptr;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        context = static_cast<TLS_CONTEXT*>(handle);
        if (TLS_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        SSL_shutdown (context->_ssl);
        SSL_free (context->_ssl);

        if (TLS_CONTEXT_CLOSESOCKET_ONDESTROY
            == (context->_flags & TLS_CONTEXT_CLOSESOCKET_ONDESTROY)) {
            close_socket (context->_socket, true, 0);
        }

        context->_signature = 0;
        delete context;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security::read (tls_context_t* handle, int mode, void* buffer, size_t buffer_size, size_t* cbread)
{
    return_t ret = errorcode_t::success;

    TLS_CONTEXT* context = nullptr;
    int ret_recv = 0;

    __try2
    {
        if (nullptr == handle || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        context = static_cast<TLS_CONTEXT*>(handle);
        if (TLS_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        if (nullptr != cbread) {
            *cbread = 0;
        }

        size_t size_read = buffer_size;
        if (TLS_READ_SOCKET_RECV & mode) {
            ret_recv = ::recv (context->_socket, (char *) buffer, buffer_size, 0);
            if (0 == ret_recv) { /* gracefully closed */
                ret = errorcode_t::disconnect;
                __leave2;
            }
            if (-1 == ret_recv) {
#if defined __linux__
                ret = get_errno (ret_recv);
#elif defined _WIN32 || defined _WIN64
                ret = GetLastError ();
#endif
                __leave2_trace (ret);
            }

            size_read = ret_recv;
            if (nullptr != cbread) {
                *cbread = ret_recv;
            }
        }
        if (TLS_READ_BIO_WRITE & mode) {
            /* SSL 을 통해 수신한 암호화 상태의 데이터 */
            BIO_write (context->_sbio_read, buffer, (int) size_read);
        }
        if (TLS_READ_SSL_READ & mode) {
            int written = BIO_number_written (context->_sbio_read);
            ret_recv = SSL_read (context->_ssl, buffer, (int) buffer_size);
            if (ret_recv <= 0) {
                int ssl_error = SSL_get_error (context->_ssl, ret_recv);
                if (SSL_ERROR_WANT_READ == ssl_error) {
                    ret = errorcode_t::pending;
                } else {
                    ret = errorcode_t::internal_error;
                }
                __leave2;
            } else {
                if (buffer_size < (size_t) written) {
                    ret = errorcode_t::more_data;
                    if (nullptr != cbread) {
                        *cbread = buffer_size;
                    }
                }
                if (nullptr != cbread) {
                    *cbread = ret_recv;
                }
            }
        }
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t transport_layer_security::send (tls_context_t* handle, int mode, const char* data, size_t size_data, size_t* size_sent)
{
    return_t ret = errorcode_t::success;
    TLS_CONTEXT* context = nullptr;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace (ret);
        }

        if (size_sent) {
            *size_sent = 0;
        }

        context = static_cast<TLS_CONTEXT*>(handle);
        if (TLS_CONTEXT_SIGNATURE != context->_signature) {
            ret = errorcode_t::invalid_context;
            __leave2_trace (ret);
        }

        if (TLS_SEND_SSL_WRITE & mode) {
            int ret_write = SSL_write (context->_ssl, data, (int) size_data);

            if (ret_write < 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl (ret);
            }
            if (size_sent) {
                *size_sent = ret_write;
            }
        }

        int written = BIO_number_written (context->_sbio_write);

        int ret_read = 0;
        std::vector <char> buf;
        buf.resize (written);

        if (TLS_SEND_BIO_READ & mode) {
            ret_read = BIO_read (context->_sbio_write, &buf [0], buf.size ());
            if (ret_read < 1) {
                ret = errorcode_t::internal_error;
                __leave2;   /* too many traces here */
            }

            if (TLS_SEND_SOCKET_SEND & mode) {
                ::send (context->_socket, &buf [0], ret_read, 0);
            }
        }

    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

socket_t transport_layer_security::get_socket (tls_context_t* handle)
{
    socket_t sock = INVALID_SOCKET;

    if (nullptr != handle) {
        sock = handle->_socket;
    }
    return sock;
}

SSL_CTX* transport_layer_security::get ()
{
    return _x509;
}

}
}  // namespace
