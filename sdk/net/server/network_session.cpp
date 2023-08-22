/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/server/network_stream.hpp>

namespace hotplace {
namespace net {

network_session::network_session (server_socket* serversocket)
{
    _shared.make_share (this);
    _session.svr_socket = serversocket;
}

network_session::~network_session ()
{
    get_server_socket ()->close ((socket_t) _session.netsock.client_socket, _session.tls_handle);
    //_session.netsock.client_socket = (handle_t)INVALID_SOCKET;
    //_session.tls_handle = nullptr;
    // do nothing
}

return_t network_session::connected (handle_t client_socket, sockaddr_storage_t* sockaddr, tls_context_t* tls_handle)
{
    return_t ret = errorcode_t::success;

    _session.netsock.client_socket = client_socket;
    memcpy (&(_session.netsock.client_addr), sockaddr, sizeof (sockaddr_storage_t));
    _session.priority = 0;
    _session.tls_handle = tls_handle;
    return ret;
}

return_t network_session::ready_to_read ()
{
    return_t dwret = errorcode_t::success;

#if defined _WIN32 || defined _WIN64
    /* asynchronous read */
    DWORD dwFlags = 0;
    DWORD dwRecvBytes = 0;
    memset (&(_session.wsabuf_pair.r), 0, sizeof (OVERLAPPED));
    _session.wsabuf_pair.r.wsabuf.len = RTL_FIELD_SIZE (net_session_wsabuf_t, buffer);
    _session.wsabuf_pair.r.wsabuf.buf = _session.wsabuf_pair.r.buffer;

    WSARecv ((socket_t) _session.netsock.client_socket, &(_session.wsabuf_pair.r.wsabuf), 1, &dwRecvBytes, &dwFlags,
             &(_session.wsabuf_pair.r.overlapped), nullptr);
#endif
    return dwret;
}

return_t network_session::send (const char* data_ptr, size_t size_data)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == data_ptr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        size_t cbsent = 0;
        ret = get_server_socket ()->send ((socket_t) _session.netsock.client_socket, _session.tls_handle, data_ptr, size_data, &cbsent);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

net_session_socket_t* network_session::socket_info ()
{
    return &_session.netsock;
}

#if defined _WIN32 || defined _WIN64
WSABUF* network_session::wsabuf_read ()
{
    return &_session.wsabuf_pair.r.wsabuf;
}
#endif

network_stream* network_session::getstream ()
{
    return &_stream;
}

network_stream* network_session::getrequest ()
{
    return &_request;
}

int network_session::get_priority ()
{
    return _session.priority;
}

void network_session::set_priority (int priority)
{
    _session.priority = priority;
}

int network_session::addref ()
{
    return _shared.addref ();
}

int network_session::release ()
{
    return _shared.delref ();
}

return_t network_session::produce (network_priority_queue* q, void* buf_read, size_t size_buf_read)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        _lock.enter ();

        if (nullptr == q) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

#if defined _WIN32 || defined _WIN64
        // buf_read, size_buf_read transmitted
#elif defined __linux__ || defined __APPLE__
        // read
        size_buf_read = RTL_NUMBER_OF (_session.buffer);
        buf_read = _session.buffer;
#endif

        return_t dwResult = errorcode_t::success;

        if (_session.tls_handle) { /* TLS */
            size_t cbread = 0;
            bool data_ready = false;
            server_socket* server_socket_intf = get_server_socket ();
            int mode = 0;
#if defined __linux__ || defined __APPLE__
            mode = TLS_READ_EPOLL;
#elif defined _WIN32 || defined _WIN64
            mode = TLS_READ_IOCP;
#endif
            ret = server_socket_intf->read ((socket_t) _session.netsock.client_socket, _session.tls_handle, mode,
                                            (char *) buf_read, size_buf_read, nullptr);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            while (true) {
                dwResult = server_socket_intf->read ((socket_t) _session.netsock.client_socket, _session.tls_handle,
                                                     TLS_READ_SSL_READ, (char *) buf_read, size_buf_read, &cbread);  /*SSL_read */
                if (errorcode_t::success == dwResult) {
                    getstream ()->produce (buf_read, cbread);
                    data_ready = true;
                } else {
                    break;
                }
            }

            if (data_ready) {
                q->push (get_priority (), this);
            }
        } else {        /* wo TLS */
            getstream ()->produce (buf_read, size_buf_read);
            q->push (get_priority (), this);
        }
    }
    __finally2
    {
        _lock.leave ();
        // do nothing
    }

    return ret;
}

return_t network_session::consume (network_protocol_group* protocol_group, network_stream_data** ptr_network_stream_buffer)
{
    return_t ret = errorcode_t::success;

    _request.read (protocol_group, &_stream);
    ret = _request.consume (ptr_network_stream_buffer);
    return ret;
}

server_socket* network_session::get_server_socket ()
{
    return _session.svr_socket;
}

network_session_data* network_session::get_session_data ()
{
    return &_session_data;
}

network_session_manager::network_session_manager ()
{
    // do nothing
}

network_session_manager::~network_session_manager ()
{
    // do nothing
}

return_t network_session_manager::connected (handle_t client_socket, sockaddr_storage_t* sockaddr, server_socket* svr_socket,
                                             tls_context_t* tls_handle, network_session** ptr_session_object)
{
    return_t ret = errorcode_t::success;
    network_session_map_pib_t pairib;
    network_session* session_object = nullptr;

    __try2
    {
        _session_lock.enter ();
        pairib = _session_map.insert (std::make_pair (client_socket, (network_session *) nullptr));
        if (true == pairib.second) {
            session_object = new network_session (svr_socket);
            pairib.first->second = session_object;
            session_object->connected (client_socket, sockaddr, tls_handle);
            *ptr_session_object = session_object;
        } else {
            ret = ERROR_ALREADY_ASSIGNED;
        }
        _session_lock.leave ();
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

return_t network_session_manager::find (handle_t client_socket, network_session** ptr_session_object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _session_lock.enter ();
        network_session_map_t::iterator iter = _session_map.find (client_socket);
        if (_session_map.end () == iter) {
            ret = errorcode_t::not_found;
        } else {
            network_session* session_object = iter->second;
            session_object->addref (); /* in-use */
            *ptr_session_object = session_object;
        }
        _session_lock.leave ();
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

network_session* network_session_manager::operator[] (handle_t client_socket)
{
    network_session* ptr_session_object = nullptr;

    find (client_socket, &ptr_session_object);
    return ptr_session_object;
}

return_t network_session_manager::ready_to_close (handle_t client_socket, network_session** ptr_session_object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == ptr_session_object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _session_lock.enter ();
        network_session_map_t::iterator iter = _session_map.find (client_socket);
        if (_session_map.end () == iter) {
            ret = errorcode_t::not_found;
        } else {
            network_session* session_object = iter->second;
            *ptr_session_object = session_object;

            _session_map.erase (iter);
        }
        _session_lock.leave ();
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

}
}  // namespace
