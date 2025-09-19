/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDAPPLICATIONDATA__
#define __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDAPPLICATIONDATA__

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshakes.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_records.hpp>

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
    tls_record_application_data(tls_session* session, const byte_t* data, size_t size);
    virtual ~tls_record_application_data();

    tls_handshakes& get_handshakes();
    tls_records& get_records();
    void set_binary(const binary_t bin);
    void set_binary(const byte_t* data, size_t size);
    const binary_t& get_binary();

    virtual void operator<<(tls_record* record);
    virtual void operator<<(tls_handshake* handshake);
    virtual tls_record& add(tls_content_type_t type, tls_session* session, std::function<return_t(tls_record*)> func = nullptr, bool upref = false);
    virtual tls_record& add(tls_hs_type_t type, tls_session* session, std::function<return_t(tls_handshake*)> func = nullptr, bool upref = false);

   protected:
    virtual return_t do_preprocess(tls_direction_t dir);
    virtual return_t do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    virtual return_t do_write_body(tls_direction_t dir, binary_t& bin);
    virtual bool apply_protection();

    return_t get_application_data(binary_t& message, bool untag);

   private:
    tls_handshakes _handshakes;
    tls_records _records;
    binary_t _bin;
};

}  // namespace net
}  // namespace hotplace

#endif
