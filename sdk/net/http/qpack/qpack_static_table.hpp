/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_QPACK_QPACKSTATICTABLE__
#define __HOTPLACE_SDK_NET_HTTP_QPACK_QPACKSTATICTABLE__

#include <hotplace/sdk/net/http/compression/http_static_table.hpp>

namespace hotplace {
namespace net {

class qpack_static_table : public http_static_table {
   public:
    static qpack_static_table* get_instance();

   protected:
    qpack_static_table();
    virtual void load();

   private:
    static qpack_static_table _instance;
};

}  // namespace net
}  // namespace hotplace

#endif
