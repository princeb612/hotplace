/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <arpa/inet.h>
#include <linux/cn_proc.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <sdk/base/stl.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/io/types.hpp>

namespace hotplace {
namespace io {

struct _NETLINK_CONTEXT;
typedef struct _NETLINK_CONTEXT netlink_t;

enum PROC_TYPE {
    PROC_FORK,
    PROC_EXEC,
    PROC_EXIT,
};

typedef struct _PROC_EVENT {
    struct proc_event proc_ev;
} PROC_EVENT;

/*
 * @brief (event-driven) process monitoring
 */
class netlink {
   public:
    netlink();
    ~netlink();

    /*
     * @brief open
     * @param netlink_t** handle [out]
     * @param uint32 flags [in]
     * @param TYPE_CALLBACK_HANDLER callback_handler [in]
     * @param void* parameter [in]
     * @return error code (see error.h)
     */
    return_t open(netlink_t** handle, uint32 flags, TYPE_CALLBACK_HANDLER callback_handler, void* parameter);
    /*
     * @brief close
     * @param netlink_t* handle [in]
     */
    return_t close(netlink_t* handle);

   protected:
    /*
     * @brief producer
     */
    static return_t producer_thread_routine(void* param);
    /*
     * @brief producer
     */
    static return_t producer_thread_signal(void* param);
    /*
     * @brief consumer
     */
    static return_t consumer_thread_routine(void* param);
    /*
     * @brief consumer
     */
    static return_t consumer_thread_signal(void* param);

    return_t netlink_open(socket_t* sock);
    return_t netlink_close(socket_t sock);
    return_t netlink_control(socket_t sock, bool enable);
};

}  // namespace io
}  // namespace hotplace
