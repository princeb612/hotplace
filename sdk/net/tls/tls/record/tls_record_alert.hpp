/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDALERT__
#define __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDALERT__

#include <sdk/net/tls/tls/record/tls_record.hpp>

namespace hotplace {
namespace net {

class tls_record_alert : public tls_record {
   public:
    tls_record_alert(tls_session* session);
    tls_record_alert(tls_session* session, uint8 level, uint8 desc);
    virtual ~tls_record_alert();

    virtual void operator<<(tls_record* record);

    virtual return_t read_plaintext(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);

    tls_record_alert& set(uint8 level, uint8 desc);
    uint8 get_level() const;
    uint8 get_desc() const;

   protected:
    virtual return_t do_postprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual bool apply_protection();

    void check_status(tls_direction_t dir);

   private:
    uint8 _level;
    uint8 _desc;
};

}  // namespace net
}  // namespace hotplace

#endif
