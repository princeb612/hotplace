/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extensions.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_builder.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_pre_shared_key.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extensions.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>
#include <set>

namespace hotplace {
namespace net {

tls_extensions::tls_extensions() {}

return_t tls_extensions::read(tls_handshake* handshake, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handshake || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // extension
        //  uint16 type
        //  uint16 len
        //  ...

        tls_extension_builder builder;
        std::set<uint16> seen_extension_types;
        while (pos < size) {
            if ((pos > size) || (size - pos < 4)) {
                ret = errorcode_t::no_more;
                break;
            }

            auto extension_type = ntoh16(*(uint16*)(stream + pos));
            if (false == seen_extension_types.insert(extension_type).second) {
                // RFC 9846 4.3: an extension block MUST NOT contain more
                // than one extension of the same type. Reject before parsing
                // the duplicate so it cannot overwrite state established by
                // the first extension (notably PSK and early-data state).
                auto session = handshake->get_session();
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                break;
            }
            t_enum_type<tls_extension_type_t> etextension_type(extension_type);
            auto extension = builder.set(handshake).set(dir).set(etextension_type).build();
            if (extension) {
                // RFC 8446 4.2.11 requires pre_shared_key to be the final
                // ClientHello extension. Check before parsing it so a server
                // never processes a binder from a structurally invalid offer.
                if ((from_client == dir) && (tls_handshake_type_t::client_hello == handshake->get_type()) && (tls_extension_type_t::pre_shared_key == etextension_type) &&
                    (ntoh16(*(uint16*)(stream + pos + 2)) != size - pos - 4)) {
                    auto session = handshake->get_session();
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    extension->release();
                    break;
                }
                // RFC 8446 4.2.9: the server must reject a PSK offer
                // without psk_key_exchange_modes before parsing/verifying
                // its binder. At this point all preceding ClientHello
                // extensions have been parsed and added to the collection.
                if ((from_client == dir) && (tls_handshake_type_t::client_hello == handshake->get_type()) && (tls_extension_type_t::pre_shared_key == etextension_type) &&
                    (nullptr == handshake->get_extensions().get(tls_extension_type_t::psk_key_exchange_modes))) {
                    auto session = handshake->get_session();
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::missing_extension);
                    session->reset_session_status();
                    ret = errorcode_t::handshake_failure;
                    extension->release();
                    break;
                }
                ret = extension->read(dir, stream, size, pos);
                if (errorcode_t::success == ret) {
                    add(extension);
                } else {
#if defined DEBUG
                    if (istraceable(trace_category_t::trace_category_net)) {
                        tls_advisor* tlsadvisor = tls_advisor::get_instance();
                        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                            dbs.println(ANSI_ESCAPE "1;31m! error while reading extension %s" ANSI_ESCAPE "0m",
                                        tlsadvisor->nameof_tls_extension(etextension_type).c_str());
                        });
                    }
#endif
                    extension->release();
                    break;
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extensions::read(tls_handshake* handshake, tls_direction_t dir, const binary_t& bin) {
    const byte_t* stream = bin.data();
    size_t size = bin.size();
    size_t pos = 0;
    return read(handshake, dir, stream, size, pos);
}

return_t tls_extensions::write(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;

    // RFC 8446 4.2.11
    // The "pre_shared_key" extension MUST be the last extension in the
    // ClientHello (this facilitates implementation as described below).
    // Servers MUST check that it is the last extension and otherwise fail
    // the handshake with an "illegal_parameter" alert.
    _extensions.move_to_back(tls_extension_type_t::pre_shared_key, [](tls_extension* ext) -> tls_extension_type_t { return ext->get_type(); });

    auto lambda = [this, &dir, &bin](tls_extension* extension) -> return_t {
        // A ClientHello without a usable resumption ticket must not carry
        // either pre_shared_key or early_data. In particular, do not serialize
        // a stale PSK extension after ClientHello preprocessing selected one_rtt.
        auto handshake = extension->get_handshake();
        if ((from_client == dir) && (nullptr != handshake) && (tls_handshake_type_t::client_hello == handshake->get_type())) {
            auto session = handshake->get_session();
            auto flow = session->get_tls_protection().get_flow();
            const auto& early_state = session->get_session_info(from_server).get_keyvalue();
            if ((tls_extension_type_t::pre_shared_key == extension->get_type()) && (tls_flow_t::hello_retry_request == flow) &&
                static_cast<tls_extension_client_psk*>(extension)->is_suppressed()) {
                return errorcode_t::success;
            }
            if (((tls_extension_type_t::pre_shared_key == extension->get_type()) && (tls_flow_t::one_rtt == flow)) ||
                ((tls_extension_type_t::early_data == extension->get_type()) &&
                 ((tls_flow_t::zero_rtt != flow) || (0 == early_state.get(session_early_data_limit)) || (nullptr == get(tls_extension_type_t::pre_shared_key))))) {
                return errorcode_t::success;
            }
        }

        // A server accepts early data only by echoing early_data in
        // EncryptedExtensions. If ticket age, ticket policy, selected identity,
        // or cipher-suite compatibility disallows it, omit the extension and
        // continue with the PSK 1-RTT handshake.
        if ((from_server == dir) && (nullptr != handshake) && (tls_handshake_type_t::encrypted_extensions == handshake->get_type()) &&
            (tls_extension_type_t::early_data == extension->get_type())) {
            auto session = handshake->get_session();
            auto& protection = session->get_tls_protection();
            const auto& early_state = session->get_session_info(from_server).get_keyvalue();
            uint16 selected_identity = t_narrow_cast(session->get_keyvalue().get(session_server_psk_selected_identity));
            uint16 ticket_cipher_suite = t_narrow_cast(session->get_keyvalue().get(session_server_psk_ticket_cipher_suite));
            tls_resumption_ticket early_ticket = session->get_early_data_ticket();
            auto alpn_extension = static_cast<tls_extension_alpn*>(get(tls_extension_type_t::application_layer_protocol_negotiation));
            binary_t negotiated_alpn = (nullptr != alpn_extension) ? alpn_extension->get_protocols() : binary_t();
            bool ticket_parameters_match = (false == early_ticket.identity.empty()) && (early_ticket.version == static_cast<uint16>(protection.get_tls_version())) &&
                                           (early_ticket.cipher_suite == protection.get_cipher_suite()) && (early_ticket.alpn == negotiated_alpn) &&
                                           (early_state.get(session_early_data_limit) <= early_ticket.max_early_data_size);
            bool accept_early_data = (tls_flow_t::zero_rtt == protection.get_flow()) && (0 == selected_identity) && (0 != early_state.get(session_early_data_offered)) &&
                                     (0 != early_state.get(session_early_data_limit)) && (0 != ticket_cipher_suite) &&
                                     (protection.get_cipher_suite() == ticket_cipher_suite) && ticket_parameters_match;
            if (false == accept_early_data) {
                return errorcode_t::success;
            }
        }

        auto ret = extension->write(dir, bin);
        if (errorcode_t::success != ret) {
#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_net)) {
                tls_advisor* tlsadvisor = tls_advisor::get_instance();
                trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    dbs.println(ANSI_ESCAPE "1;31m! error while writing extension %s" ANSI_ESCAPE "0m", tlsadvisor->nameof_tls_extension(extension->get_type()).c_str());
                });
            }
#endif
        } else if ((from_server == dir) && (nullptr != handshake) && (tls_handshake_type_t::encrypted_extensions == handshake->get_type()) &&
                   (tls_extension_type_t::early_data == extension->get_type())) {
            handshake->get_session()->get_session_info(from_server).get_keyvalue().set(session_early_data_accepted, 1);
        } else if ((from_client == dir) && (nullptr != handshake) && (tls_handshake_type_t::client_hello == handshake->get_type()) &&
                   (tls_extension_type_t::early_data == extension->get_type())) {
            // Remember the local offer so the client can validate the server's
            // EncryptedExtensions acceptance indication.
            auto& early_state = handshake->get_session()->get_session_info(from_server).get_keyvalue();
            early_state.set(session_early_data_offered, 1);
            early_state.set(session_early_data_offered_initial, 1);
        }
        return ret;
    };
    tls_session* write_session = nullptr;
    uint64 previous_early_data_accepted = 0;
    uint64 previous_early_data_offered = 0;
    uint64 previous_early_data_offered_initial = 0;
    uint64 previous_record_size_limit = 0;
    binary_t previous_alpn;
    bool previous_alpn_present = false;
    bool early_data_state_snapshotted = false;
    bool encrypted_extensions_state_snapshotted = false;
    auto write_extension = [&](tls_extension* extension) -> return_t {
        if (false == early_data_state_snapshotted) {
            auto handshake = extension ? extension->get_handshake() : nullptr;
            write_session = handshake ? handshake->get_session() : nullptr;
            if (write_session) {
                auto& early_state = write_session->get_session_info(from_server).get_keyvalue();
                previous_early_data_accepted = early_state.get(session_early_data_accepted);
                previous_early_data_offered = early_state.get(session_early_data_offered);
                previous_early_data_offered_initial = early_state.get(session_early_data_offered_initial);
                early_data_state_snapshotted = true;

                if ((from_server == dir) && (tls_handshake_type_t::encrypted_extensions == handshake->get_type())) {
                    previous_record_size_limit = write_session->get_session_info(dir).get_keyvalue().get(session_record_size_limit);
                    previous_alpn_present = (errorcode_t::success == write_session->get_tls_protection().get_secrets().peek(tls_secret_t::alpn, previous_alpn));
                    encrypted_extensions_state_snapshotted = true;
                }
            }
        }
        return lambda(extension);
    };
    ret = for_each(write_extension);
    if ((errorcode_t::success != ret) && early_data_state_snapshotted) {
        // Extension writers may provisionally update session state while
        // serializing individual extensions. Roll it back if a later writer
        // prevents the complete extension block from being emitted.
        auto& early_state = write_session->get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_accepted, previous_early_data_accepted);
        early_state.set(session_early_data_offered, previous_early_data_offered);
        early_state.set(session_early_data_offered_initial, previous_early_data_offered_initial);
        if (encrypted_extensions_state_snapshotted) {
            write_session->get_session_info(dir).get_keyvalue().set(session_record_size_limit, previous_record_size_limit);
            auto& secrets = write_session->get_tls_protection().get_secrets();
            if (previous_alpn_present) {
                secrets.assign(tls_secret_t::alpn, previous_alpn);
            } else {
                secrets.erase(tls_secret_t::alpn);
            }
        }
    }
    return ret;
}

return_t tls_extensions::add(tls_extension* extension, bool upref) { return _extensions.add(extension, upref); }

tls_extensions& tls_extensions::add(tls_extension_type_t type, tls_direction_t dir, tls_handshake* handshake, std::function<return_t(tls_extension*)> func, bool upref) {
    __try2 {
        tls_extension_builder builder;
        auto extension = builder.set(type).set(dir).set(handshake).build();
        if (extension) {
            if (func) {
                auto test = func(extension);
                if (errorcode_t::success != test) {
#if defined DEBUG
                    tls_advisor* tlsadvisor = tls_advisor::get_instance();
                    if (istraceable(trace_category_t::trace_category_net)) {
                        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_extension,
                                          [&](basic_stream& dbs) -> void { dbs.println("check %s", tlsadvisor->nameof_tls_extension(type).c_str()); });
                    }
#endif
                    extension->release();
                    __leave2;
                }
            }
            _extensions.add(extension, upref);
        }
    }
    __finally2 {}
    return *this;
}

tls_extensions& tls_extensions::operator<<(tls_extension* extension) {
    add(extension);
    return *this;
}

tls_extensions& tls_extensions::operator<<(tls_extensions* extensions) {
    if (extensions) {
        auto lambda = [this, &extensions](tls_extension* ext) -> return_t { return add(ext, true); };

        extensions->for_each(lambda);
    }
    return *this;
}

return_t tls_extensions::for_each(std::function<return_t(tls_extension*)> func) { return _extensions.for_each(func); }

tls_extension* tls_extensions::get(tls_extension_type_t type, bool upref) { return _extensions.get(type, upref); }

tls_extension* tls_extensions::getat(size_t index, bool upref) { return _extensions.getat(index, upref); }

tls_extension* tls_extensions::operator[](size_t index) { return _extensions[index]; }

bool tls_extensions::find(tls_extension_type_t type, std::vector<size_t>& indexes, size_t& size) { return _extensions.find(type, indexes, size); }

bool tls_extensions::empty() const { return _extensions.empty(); }

size_t tls_extensions::size() const { return _extensions.size(); }

void tls_extensions::clear() { _extensions.clear(); }

}  // namespace net
}  // namespace hotplace
