/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_record_builder.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDBUILDER__
#define __HOTPLACE_SDK_NET_TLS_TLS_RECORD_TLSRECORDBUILDER__

#include <hotplace/sdk/net/tls/tls/types.hpp>

namespace hotplace {
namespace net {

/**
 * @example
 *          // read
 *          size_t pos = 0;
 *          while (pos < size) {
 *              uint8 content_type = stream[pos];
 *              tls_record_builder builder;
 *              auto record = builder.set(session).set(content_type).build();
 *              if (record) {
 *                  ret = record->read(from_server, stream, size, pos);
 *                  record->release();
 *              }
 *          }
 */
class HOTPLACE_NET_API tls_record_builder {
   public:
    tls_record_builder();

    tls_record_builder& set(tls_session* session);
    tls_record_builder& set(tls_content_type_t type);
    /**
     * @brief   set direction (C->S, S->C)
     * @remarks get directional record-protection state from session
     *          TLS 1.2 activates it at ChangeCipherSpec. TLS 1.3 ignores compatibility CCS:
     *          early data activates the client direction after ClientHello; handshake protection activates after ServerHello.
     *          auto apply_protection = session->get_session_info(dir).apply_protection();
     *          if (is_kindof_tls13 && apply_protection) {
     *              // new tls_record_application_data
     *          } else {
     *              // new tls_record_handshake or new tls_record_alert
     *          }
     * @example
     *          auto record = builder.set(session).set(tls_content_type_t::handshake).set(from_client).construct().build()
     *          auto record = builder.set(session).set(tls_content_type_t::alert).set(from_client).construct().build()
     */
    tls_record_builder& set(tls_direction_t dir);
    /**
     * @brief   construct TLS record
     * @remarks
     *          | spec    | activation point                   | record                          | handshake                  |
     *          | TLS 1.3 | after ClientHello (early_data)     | new tls_record_application_data | client early traffic       |
     *          | TLS 1.3 | after ServerHello                  | new tls_record_application_data | handshake traffic          |
     *          | TLS 1.3 | before ServerHello (no early_data) | new tls_record_handshake        | unprotected                |
     *          | TLS 1.2 | after CCS                          | new tls_record_handshake        | protected                  |
     *          | TLS 1.2 | before CCS                         | new tls_record_handshake        | unprotected                |
     *
     * @example
     *          // change_cipher_spec here
     *
     *          tls_record_builder builder;
     *          auto record = builder.set(session).set(tls_content_type_t::handshake).set(from_client).construct().build();
     *          if (record) {
     *              *record << new tls_handshake_finished(session);
     *              record->write(dir, bin);
     *              record->release();
     *          }
     */
    tls_record_builder& construct(bool flag = true);
    /*
     * @brief   set state to [change cipher spec]
     * @example
     *          builder  //
     *              .set(dir)
     *              .construct()
     *              .add(&records, tls_content_type_t::change_cipher_spec, session)
     *              .set_protected(true)
     *              .add(&records, tls_content_type_t::handshake, session,  //
     *                   [&](tls_record* record) -> return_t {
     *                       record->add(tls_handshake_type_t::finished, session);
     *                       return errorcode_t::success;
     *                   });
     */
    tls_record_builder& set_protected(bool protect);
    /**
     * @brief   add record into tls_records
     * @param   tls_records* records [in]
     * @param   tls_content_type_t type [in]
     * @param   tls_session* session [in]
     * @param   std::function<return_t(tls_record*)> func [inopt]
     * @example
     *          tls_record_builder builder;
     *          tls_records records;
     *                  builder                                                  //
     *                      .add(&records, tls_content_type_t::handshake, session,  //
     *                           [&](tls_record* record) -> return_t {
     *                               return_t ret = errorcode_t::success;
     *                               tls_handshake* handshake = nullptr;
     *                               ret = construct_server_hello(&handshake, session, nullptr, _minspec, _maxspec);
     *                               if (errorcode_t::success == ret) {
     *                                   *record << handshake;
     *                               }
     *                               return ret;
     *                           });
     */
    tls_record_builder& add(tls_records* records, tls_content_type_t type, tls_session* session, std::function<return_t(tls_record*)> func = nullptr);

    tls_record* build();
    tls_record* build(tls_content_type_t type, tls_session* session, std::function<return_t(tls_record*)> func = nullptr);

    tls_session* get_session() const;
    tls_content_type_t get_type() const;
    tls_direction_t get_direction() const;
    bool is_construct() const;
    bool is_protected() const;

   private:
    tls_session* _session;
    tls_content_type_t _type;
    tls_direction_t _dir;
    bool _construct;
    bool _protected;
};

}  // namespace net
}  // namespace hotplace

#endif
