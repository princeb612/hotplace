/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_record_alert.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDALERT__
#define __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDALERT__

#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>

namespace hotplace {
namespace net {

class tls_record_alert : public tls_record {
   public:
    tls_record_alert(tls_session* session);
    tls_record_alert(tls_session* session, tls_alertlevel_t level, tls_alertdesc_t desc);
    virtual ~tls_record_alert();

    virtual void operator<<(tls_record* record);

    virtual return_t read_plaintext(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);

    tls_record_alert& set(tls_alertlevel_t level, tls_alertdesc_t desc);
    tls_alertlevel_t get_level() const;
    tls_alertdesc_t get_desc() const;

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual bool apply_protection();

    void check_status(tls_direction_t dir);

   private:
    tls_alertlevel_t _level;
    tls_alertdesc_t _desc;
};

}  // namespace net
}  // namespace hotplace

#endif
