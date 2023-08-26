/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_SERVER_NETWORKPRIORITYQUEUE__
#define __HOTPLACE_SDK_NET_SERVER_NETWORKPRIORITYQUEUE__

#include <hotplace/sdk/io/basic/mlfq.hpp>

namespace hotplace {
using namespace io;
namespace net {

class network_session;
/*
 * @brief priority queue
 * @remarks
 *          implements prosumer pattern
 *
 *          // model & reference counter
 *          thread#1 (produce)
 *              pq.push (pri, session); // increase
 *          thread#2 (consume)
 *              pq.pop (&pri, &session);
 *              if (session)
 *              {
 *                  do_something ();
 *                  session->release (); // decrease
 *              }
 */
class network_priority_queue
{
public:
    network_priority_queue ();
    ~network_priority_queue ();

    /*
     * @brief push
     * @param   int               priority    [IN]
     * @param   network_session*   token       [IN] referenced
     */
    return_t push (int priority, network_session* token);
    /*
     * @brief pop
     * @param   int*              priority    [OUT]
     * @param   network_session**  token       [OUT]
     * @remarks
     *          ret = pq.pop (&pri, &session_object);
     *          if (errorcode_t::success == ret)
     *          {
     *              // do something
     *              session_object->release ();
     *          }
     */
    return_t pop (int* priority, network_session** ptr_token);
    /*
     * @brief pop
     * @remarks
     *          network_session* session_object = prique.pop ();
     *          if (nullptr != session_object)
     *          {
     *              int pri = session_object->get_priority ();
     *          }
     */
    network_session* pop ();

    size_t size ();

protected:
    t_mlfq <network_session> _mfq;
};

}
}  // namespace

#endif
