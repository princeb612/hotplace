/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_SERVER_NETWORKPROTOCOL__
#define __HOTPLACE_SDK_NET_SERVER_NETWORKPROTOCOL__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/stream/buffer_stream.hpp>

namespace hotplace {
using namespace io;
namespace net {

enum protocol_state_t {
    protocol_state_invalid = 0, /* unknown state */
    protocol_state_ident,       /* iskindof returns IDENT */
    protocol_state_header,      /* header completed */
    protocol_state_data,        /* data complete */
    protocol_state_complete,    /* all data complete */
    protocol_state_forged,      /* forgery */
    protocol_state_crash,       /* reserved */
};

/*
 * network_multiplexer_processor data structures
 */

/* windows overlapped */
#if defined _WIN32 || defined _WIN64
typedef struct _net_session_wsabuf_t {
    OVERLAPPED overlapped;
    WSABUF wsabuf;
    char buffer[1 << 10];
} net_session_wsabuf_t;

typedef struct _net_session_wsabuf_pair_t {
    net_session_wsabuf_t r;
    net_session_wsabuf_t w;
} net_session_wsabuf_pair_t;

#endif

typedef struct _net_session_socket_t {
    handle_t client_socket;
    sockaddr_storage_t client_addr; // both ipv4 and ipv6

} net_session_socket_t;

class server_socket;
typedef struct _net_session_t {
    net_session_socket_t netsock;
    void* mplexer_handle;

#if defined _WIN32 || defined _WIN64
    net_session_wsabuf_pair_t wsabuf_pair;
#elif defined __linux__
    char buffer[1 << 10];
#endif

    server_socket* svr_socket;
    tls_context_t* tls_handle;
    int priority;
    reference_counter refcount;

} net_session_t;

class network_session;
class network_session_manager;
class network_stream;

class network_protocol
{
public:
    network_protocol ()
    {
        _shared.make_share (this);
    }
    virtual ~network_protocol ();

    /*
     * @brief check protocol
     * @param   void*           stream          [IN]
     * @param   size_t          stream_size     [IN]
     * @return  errorcode_t::success
     *          errorcode_t::not_supported (if error, do not return errorcode_t::success)
     */
    virtual return_t is_kind_of (void* stream, size_t stream_size)
    {
        return errorcode_t::success;
    }
    /*
     * @brief read stream
     * @param   IBufferStream*  stream          [IN]
     * @param   size_t*         request_size    [IN]
     * @param   protocol_state_t* state           [OUT]
     */
    virtual return_t read_stream (buffer_stream* stream, size_t* request_size, protocol_state_t* state)
    {
        *state = protocol_state_t::protocol_state_complete;
        return errorcode_t::success;
    }
    /*
     * @brief   id
     * @remarks default port number
     */
    virtual uint32 protocol_id ()
    {
        return 0;
    }

    int addref ()
    {
        return _shared.addref ();
    }
    int release ()
    {
        return _shared.delref ();
    }

protected:
    t_shared_reference <network_protocol> _shared;
};

class network_protocol_group
{
public:
    network_protocol_group ();
    virtual ~network_protocol_group ();

    /*
     * @brief add protocol
     * @param   network_protocol*    protocol        [IN] add protocol and increase reference counter
     * @return error code (see error.hpp)
     */
    virtual return_t add (network_protocol* protocol);
    /*
     * @brief operator <<
     * @param   network_protocol*    protocol        [IN]
     * @remarks
     *          add method replacement wo checking return code
     */
    virtual network_protocol_group& operator << (network_protocol* protocol);
    /*
     * @brief find
     * @param   uint32                   protocol_id     [IN]
     * @param   network_protocol**   ptr_protocol    [OUT] referenced, call release
     * @return error code (see error.hpp)
     */
    virtual return_t find (uint32 protocol_id, network_protocol** ptr_protocol);
    /*
     * @brief operator[protocol_id]
     * @sample
     *          network_protocol* protocol = protocol_group[80];
     *          if (nullptr != protocol)
     *          {
     *              //...
     *              prtotocol->release (); // decrease reference counter
     *          }
     */
    virtual network_protocol* operator[] (uint32 protocol_id);
    /*
     * @brief remove protocol
     * @param   network_protocol*    protocol        [IN] remove protocol and decrease reference counter
     * @return error code (see error.hpp)
     */
    virtual return_t remove (network_protocol* protocol);
    /*
     * @brief remove all protocol
     * @return error code (see error.hpp)
     */
    virtual return_t clear ();
    /*
     * @brief is protocol absent
     */
    virtual bool empty ();

    /*
     * @brief find appropriate protocol
     * @param   void*                   stream          [IN]
     * @param   size_t                  stream_size     [IN]
     * @param   network_protocol**   ptr_protocol    [OUT] referenced, use release to free (important)
     * @return error code (see error.hpp)
     * @remarks
     *          if input stream is too short, return errorcode_t::more_data
     */
    virtual return_t is_kind_of (void* stream, size_t stream_size, network_protocol** ptr_protocol);

    /*
     * @brief increase reference counter
     */
    int addref ();
    /*
     * @brief decrease reference counter. if reference counter 0, delete object.
     */
    int release ();

protected:
    t_shared_reference < network_protocol_group> _shared;

    typedef std::map<uint32, network_protocol*> protocol_map_t;
    typedef std::pair<protocol_map_t::iterator, bool> protocol_map_pib_t;

    critical_section _lock;
    protocol_map_t _protocols;
};

}
}  // namespace

#endif
