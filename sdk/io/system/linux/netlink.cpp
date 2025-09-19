/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#if __GLIBC__ > 4

#include <errno.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/base/system/signalwait_threads.hpp>
#include <hotplace/sdk/io/system/linux/netlink.hpp>
#include <hotplace/sdk/io/system/socket.hpp>
#include <queue>

namespace hotplace {
namespace io {

typedef std::queue<PROC_EVENT> PROC_EVENTS;
typedef struct _NETLINK_CONTEXT {
    uint32 flags;
    TYPE_CALLBACK_HANDLER consumer_handler;
    void *parameter;
    socket_t sock;
    critical_section lock;
    PROC_EVENTS que;
    signalwait_threads producer;
    signalwait_threads consumer;
    int producer_loop;
    int consumer_loop;
    unsigned long cooldown;

    _NETLINK_CONTEXT() : flags(0), consumer_handler(NULL), parameter(NULL), sock(0), producer_loop(1), consumer_loop(1), cooldown(10) {}
} NETLINK_CONTEXT;

netlink::netlink() {}

netlink::~netlink() {}

return_t netlink::open(netlink_t **handle, uint32 flags, TYPE_CALLBACK_HANDLER consumer_handler, void *parameter) {
    return_t ret = errorcode_t::success;
    NETLINK_CONTEXT *context = NULL;

    __try2 {
        if (NULL == handle || NULL == consumer_handler) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace(ret);
        }

        __try_new_catch(context, new NETLINK_CONTEXT, ret, __leave2);

        context->flags = flags;
        context->consumer_handler = consumer_handler;
        context->parameter = parameter;

        context->producer_loop = 1;
        context->consumer_loop = 1;

        socket_t sock = 0;
        ret = netlink_open(&sock);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }
        context->sock = sock;

        context->producer.set(1, producer_thread_routine, producer_thread_signal, context);
        context->consumer.set(1, consumer_thread_routine, consumer_thread_signal, context);
        context->producer.create();
        context->consumer.create();

        ret = netlink_control(sock, true);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (context) {
                delete context;
            }
        }
    }

    return ret;
}

return_t netlink::close(netlink_t *handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (NULL == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        NETLINK_CONTEXT *context = static_cast<NETLINK_CONTEXT *>(handle);

        netlink_control(context->sock, false);  // stop event notificaion
        netlink_close(context->sock);

        context->producer.signal_and_wait_all();  // stop all producer threads
        context->consumer.signal_and_wait_all();  // stop all consumer threads

        PROC_EVENTS empty;
        context->lock.enter();
        std::swap(context->que, empty);
        context->lock.leave();

        context = static_cast<NETLINK_CONTEXT *>(handle);
        delete context;
    }
    __finally2 {}

    return ret;
}

return_t netlink::producer_thread_routine(void *param) {
    return_t ret = errorcode_t::success;
    int rc = 0;

    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__((__packed__)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;
    __try2 {
        if (NULL == param) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        NETLINK_CONTEXT *context = static_cast<NETLINK_CONTEXT *>(param);

        while (1) {
            if (0 == context->producer_loop) {
                break;
            }

            if (0 != wait_socket(context->sock, 100, SOCK_WAIT_READABLE)) {
                continue;
            }

            rc = recv(context->sock, &nlcn_msg, sizeof(nlcn_msg), 0);
            if (0 == rc) {
                /* shutdown? */
                break;
            } else if (-1 == rc) {
                if (EINTR == errno) {
                    continue;
                }
                break;
            }

            switch (nlcn_msg.proc_ev.what) {
                case proc_event::PROC_EVENT_FORK:
                case proc_event::PROC_EVENT_EXEC:
                case proc_event::PROC_EVENT_EXIT:
                case proc_event::PROC_EVENT_UID:
                case proc_event::PROC_EVENT_GID:
                    context->lock.enter();
                    PROC_EVENT event;
                    memcpy(&event.proc_ev, &nlcn_msg.proc_ev, sizeof(struct proc_event));
                    context->que.push(event);
                    context->lock.leave();
                    break;
                case proc_event::PROC_EVENT_NONE:
                default:
                    break;
            }
        };
    }
    __finally2 {}
    return ret;
}

return_t netlink::producer_thread_signal(void *param) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (NULL == param) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        NETLINK_CONTEXT *context = static_cast<NETLINK_CONTEXT *>(param);

        context->producer_loop = 0;
        // context->producer_sem.signal ();
    }
    __finally2 {}
    return ret;
}

return_t netlink::consumer_thread_routine(void *param) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (NULL == param) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        NETLINK_CONTEXT *context = static_cast<NETLINK_CONTEXT *>(param);

        while (1) {
            if (0 == context->consumer_loop) {
                break;
            }

            return_t test = errorcode_t::success;
            PROC_EVENT event;
            context->lock.enter();
            if (context->que.empty()) {
                test = errorcode_t::no_data;
            } else {
                event = context->que.front();
                context->que.pop();
            }
            context->lock.leave();

            if (errorcode_t::success == test) {
                context->consumer_handler(0, &event, context->parameter);
            } else {
                msleep(context->cooldown);
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t netlink::consumer_thread_signal(void *param) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (NULL == param) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        NETLINK_CONTEXT *context = static_cast<NETLINK_CONTEXT *>(param);

        context->consumer_loop = 0;
    }
    __finally2 {}
    return ret;
}

return_t netlink::netlink_open(socket_t *sock) {
    return_t ret = errorcode_t::success;
    int nl_sock = 0;

    __try2 {
        if (NULL == sock) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace(ret);
        }

        int rc = 0;
        struct sockaddr_nl sa_nl;
        nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
        ret = get_lasterror(nl_sock);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        sa_nl.nl_family = AF_NETLINK;
        sa_nl.nl_groups = CN_IDX_PROC;
        sa_nl.nl_pid = getpid();
        rc = bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl));  // sudo required
        ret = get_lasterror(rc);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        *sock = nl_sock;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (0 != nl_sock) {
                ::close(nl_sock);
            }
        }
    }
    return ret;
}

return_t netlink::netlink_close(socket_t sock) {
    return_t ret = errorcode_t::success;

    if (0 != sock) {
        ::close(sock);
    }
    return ret;
}

return_t netlink::netlink_control(socket_t sock, bool enable) {
    return_t ret = errorcode_t::success;

    __try2 {
        int rc = 0;
        struct __attribute__((aligned(NLMSG_ALIGNTO))) {
            struct nlmsghdr nl_hdr;
            struct __attribute__((__packed__)) {
                struct cn_msg cn_msg;
                enum proc_cn_mcast_op cn_mcast;
            };
        } nlcn_msg;

        memset(&nlcn_msg, 0, sizeof(nlcn_msg));
        nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
        nlcn_msg.nl_hdr.nlmsg_pid = getpid();
        nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;
        nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
        nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
        nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);
        nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;
        rc = send(sock, &nlcn_msg, sizeof(nlcn_msg), 0);
        ret = get_lasterror(rc);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace io
}  // namespace hotplace

#endif