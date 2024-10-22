/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * spec list
 *      qop=auth
 *      algorithm=MD5|MD5-sess|SHA-256|SHA-256-sess
 *      userhash
 * todo list
 *      qop=auth-int
 *      nextnonce
 */

#ifndef __HOTPLACE_SDK_BASE_UNITTEST_TRACEABLE__
#define __HOTPLACE_SDK_BASE_UNITTEST_TRACEABLE__

#include <sdk/net/types.hpp>

namespace hotplace {

enum trace_category_t {
    // 0~63 reserve
    category_net_session = 64,
    category_http_server,
    category_http_request,
    category_http_response,
    category_header_compression,
    category_http2_push,
};

class traceable {
   public:
    traceable();
    traceable(const traceable& rhs);

    /**
     * @brief   istraceable
     */
    bool istraceable();
    /**
     * @brief   settrace
     * @param   std::function<void(trace_category_t category, uint32 events, stream_t* s)> f [in]
     */
    void settrace(std::function<void(trace_category_t category, uint32 events, stream_t* s)> f);
    /**
     * @brief   settrace
     */
    void settrace(traceable* diag);
    /**
     * @brief   event
     * @param   trace_category_t category [in]
     * @param   uint32 events [in]
     * @param   stream_t* [in]
     */
    void traceevent(trace_category_t category, uint32 events, stream_t*);

   protected:
    std::function<void(trace_category_t, uint32, stream_t*)> _df;
};

}  // namespace hotplace

#endif
