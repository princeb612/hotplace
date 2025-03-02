/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLSRECORD_APPLICATION_DATA__
#define __HOTPLACE_SDK_NET_TLS_TLSRECORD_APPLICATION_DATA__

#include <sdk/base/basic/binary.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshakes.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_records.hpp>

namespace hotplace {
namespace net {

/**
 * @sample
 *          // wrapped application data
 *          tls_record_application_data record(session);
 *          record.get_records().add(new tls_record_application_data(session. "ping");
 *          record.write(dir, bin);
 */
class tls_record_application_data : public tls_record {
   public:
    tls_record_application_data(tls_session* session);
    tls_record_application_data(tls_session* session, const std::string& data);
    tls_record_application_data(tls_session* session, const binary_t& data);

    tls_handshakes& get_handshakes();
    tls_records& get_records();
    void set_binary(const binary_t bin);
    const binary_t& get_binary();

   protected:
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);

    return_t get_application_data(binary_t& message, bool untag);

   private:
    tls_handshakes _handshakes;
    tls_records _records;
    binary_t _bin;
};

}  // namespace net
}  // namespace hotplace

#endif
