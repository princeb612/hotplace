/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_SERVER_NETWORKSTREAM__
#define __HOTPLACE_SDK_NET_SERVER_NETWORKSTREAM__

#include <hotplace/sdk/net/types.hpp>

namespace hotplace {
namespace net {

/*
 * @brief stream data that produced and consumed by network_stream
 */
class network_stream_data
{
    friend class network_stream;
public:
    network_stream_data ();
    ~network_stream_data ();

    /*
     * @brief assign
     * @param   void*   ptr     [IN]
     * @param   size_t  size    [IN]
     */
    return_t assign (void* ptr, size_t size);
    /*
     * @brief content size
     */
    size_t size ();
    /*
     * @brief content
     */
    void* content ();

    /*
     * @brief next node
     */
    network_stream_data* next ();

    /*
     * @brief destruct
     */
    void release ();

protected:
    void* _ptr;
    size_t _size;
    network_stream_data* _next;
};

/*
 * @brief network_stream_data container
 *        member of network_session
 */
class network_stream
{
public:
    network_stream ();
    ~network_stream ();

    /*
     * @brief produce
     * @param   void*   buf_read        [IN]
     * @param   size_t  size_buf_read   [IN]
     */
    return_t produce (void* buf_read, size_t size_buf_read);
    /*
     * @brief data ready
     */
    bool ready ();
    /*
     * @brief consume
     * @param   network_stream_data**  ptr_buffer_object   [OUT] use release to free
     * @return error code (see error.hpp)
     * @remarks
     *          network_stream_data* buffer;
     *          stream.consume (&buffer);
     *          while (buffer)
     *          {
     *              item = buffer;
     *              do_something (item->content(), item->size());
     *              buffer = buffer->next ();
     *              item->release ();
     *          }
     */
    return_t consume (network_stream_data** ptr_buffer_object);
    /*
     * @brief read from stream using protocol interpreter
     * @param   network_protocol_group* protocol_group  [IN]
     * @param   network_stream*        from            [IN]
     * @return error code (see error.hpp)
     */
    return_t read (network_protocol_group* protocol_group, network_stream* from);
    /*
     * @brief write into stream using protocol interpreter
     * @param   network_protocol_group* protocol_group  [IN]
     * @param   network_stream*        target          [IN]
     * @return error code (see error.hpp)
     */
    return_t write (network_protocol_group* protocol, network_stream* target);

protected:
    /*
     * @brief write if no protocol interpreter exist
     * @param   network_protocol_group* protocol        [IN]
     * @param   network_stream*        target          [OUT]
     * @return error code (see error.hpp)
     */
    return_t write_wo_protocol (network_protocol_group* protocol, network_stream* target);
    /*
     * @brief write using protocol interpreter
     * @param   network_protocol_group* protocol        [IN]
     * @param   network_stream*        target          [OUT]
     * @return error code (see error.hpp)
     */
    return_t write_with_protocol (network_protocol_group* protocol, network_stream* target);

    typedef std::list<network_stream_data*> network_stream_list_t;

    critical_section _lock;
    network_stream_list_t _queue;
};

}
}  // namespace

#endif
