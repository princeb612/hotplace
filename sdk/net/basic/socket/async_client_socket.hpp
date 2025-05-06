/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_ASYNCCLIENTSOCKET__
#define __HOTPLACE_SDK_NET_BASIC_ASYNCCLIENTSOCKET__

#include <queue>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/semaphore.hpp>
#include <sdk/base/system/thread.hpp>
#include <sdk/io/system/multiplexer.hpp>
#include <sdk/net/basic/client_socket.hpp>

namespace hotplace {
namespace net {

class async_client_socket : public client_socket {
   public:
    virtual ~async_client_socket();

    /**
     * @brief   open
     */
    virtual return_t open(sockaddr_storage_t* sa, const char* address, uint16 port);
    /**
     * @brief   connect
     */
    virtual return_t connect(const char* address, uint16 port, uint32 timeout);
    /**
     * @brief   close
     */
    virtual return_t close();

    /**
     * @brief   read
     */
    virtual return_t read(char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   more
     */
    virtual return_t more(char* ptr_data, size_t size_data, size_t* cbread);
    /**
     * @brief   send
     */
    virtual return_t send(const char* ptr_data, size_t size_data, size_t* cbsent);

    /**
     * @brief   recvfrom
     */
    virtual return_t recvfrom(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    /**
     * @brief   sendto
     */
    virtual return_t sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen);

    virtual socket_t get_socket();

   protected:
    async_client_socket();

    virtual return_t do_handshake();
    virtual return_t do_read(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen);
    virtual return_t do_secure();
    virtual return_t do_shutdown();
    virtual return_t do_close();

    return_t start_consumer();
    return_t stop_consumer();

    static return_t producer_thread(void* param);
    return_t producer_routine(void* param);
    static return_t consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context);
    return_t do_consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context);
    void async_read();

   protected:
    socket_t _fd;
    sockaddr_storage_t _sa;
    multiplexer_context_t* _mphandle;
    thread* _thread;

    // WIN32 IOCP key
    struct mplexer_key {
        netbuffer_t buffer;
        sockaddr_storage_t addr;
    };
    typedef struct mplexer_key mplexer_key_t;
    mplexer_key_t _mplexer_key;

    // queue
    struct bufferqueue_item {
        basic_stream buffer;
        sockaddr_storage_t addr;  // UDP
    };
    typedef struct bufferqueue_item bufferqueue_item_t;

    void enqueue(bufferqueue_item_t& item, const char* buf, size_t size);

    critical_section _rlock;
    std::queue<bufferqueue_item_t> _rq;
    semaphore _rsem;
};

}  // namespace net
}  // namespace hotplace

#endif
