/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_ack.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_builder.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_crypto.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_padding.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>
#include <sdk/net/tls/quic/packet/quic_packet_builder.hpp>
#include <sdk/net/tls/quic_packet_publisher.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

quic_packet_publisher::quic_packet_publisher() : _session(nullptr), _payload_size(0), _flags(0) {}

quic_packet_publisher& quic_packet_publisher::set_session(tls_session* session) {
    _session = session;
    return *this;
}

quic_packet_publisher& quic_packet_publisher::set_payload_size(uint16 size) {
    _payload_size = size;
    return *this;
}

quic_packet_publisher& quic_packet_publisher::set_flags(uint32 flags) {
    _flags = flags;
    return *this;
}

tls_session* quic_packet_publisher::get_session() { return _session; }

uint16 quic_packet_publisher::get_payload_size() { return _payload_size; }

uint32 quic_packet_publisher::get_flags() { return _flags; }

tls_handshakes& quic_packet_publisher::get_handshakes() { return _handshakes; }

http3_frames& quic_packet_publisher::get_frames() { return _frames; }

quic_packet_publisher& quic_packet_publisher::add(tls_handshake* handshake, bool upref) {
    _handshakes.add(handshake, upref);
    return *this;
}

quic_packet_publisher& quic_packet_publisher::add(http3_frame* frame, bool upref) {
    _frames.add(frame, upref);
    return *this;
}

quic_packet_publisher& quic_packet_publisher::operator<<(tls_handshake* handshake) {
    _handshakes.add(handshake);
    return *this;
}

quic_packet_publisher& quic_packet_publisher::operator<<(http3_frame* frame) {
    _frames.add(frame);
    return *this;
}

return_t quic_packet_publisher::probe_spaces(std::set<protection_space_t>& spaces) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (false == get_handshakes().empty()) {
            // initial or handshake
            std::set<protection_space_t> temp;
            ret = get_handshakes().for_each([&](tls_handshake* handshake) -> return_t {
                temp.insert(is_kindof_initial(handshake) ? protection_initial : protection_handshake);
                return (1 == temp.size()) ? success : bad_request;
            });
            if (errorcode_t::success != ret) {
                __leave2;
            }

            spaces = temp;
        }
        if (false == get_frames().empty()) {
            // application (1-RTT)
            spaces.insert(protection_application);
        }

        // ack
        if (quic_ack_packet & get_flags()) {
            auto lambda_ack = [&](tls_session* session, protection_space_t space) -> return_t {
                return_t test = success;
                auto& pkns = session->get_quic_session().get_pkns(space);
                critical_section_guard guard(pkns.get_lock());
                if (false == pkns.is_modified()) {
                    test = do_nothing;
                } else {
                    spaces.insert(space);
                }
                return test;
            };

            ret = lambda_ack(get_session(), protection_initial);
            if (errorcode_t::success == ret) {
                __leave2;
            }
            ret = lambda_ack(get_session(), protection_handshake);
            if (errorcode_t::success == ret) {
                __leave2;
            }
            ret = lambda_ack(get_session(), protection_application);
            if (errorcode_t::success == ret) {
                __leave2;
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_packet_publisher::publish_space(protection_space_t space, tls_direction_t dir, std::list<binary_t>& container) {
    return_t ret = errorcode_t::success;
    __try2 {
#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("publish QUIC");
            trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
        }
#endif

        auto session = get_session();
        auto tlsadvisor = tls_advisor::get_instance();
        quic_packet_t type = quic_packet_type_initial;
        switch (space) {
            case protection_initial: {
                type = quic_packet_type_initial;
            } break;
            case protection_handshake: {
                type = quic_packet_type_handshake;
            } break;
            case protection_application: {
                type = quic_packet_type_1_rtt;
            } break;
        }

        quic_packet_builder packet_builder;
        quic_frame_builder frame_builder;

        auto packet = packet_builder.set(type).set_session(session).set(dir).construct().build();
        if (packet) {
            // ack
            if (quic_ack_packet & get_flags()) {
                auto& pkns = session->get_quic_session().get_pkns(space);
                critical_section_guard guard(pkns.get_lock());
                if (pkns.is_modified()) {
                    auto frame = (quic_frame_ack*)frame_builder.set(quic_frame_type_ack).set(packet).build();
                    frame->set_protection_level(space);
                    *packet << frame;
#if defined DEBUG
                    if (istraceable(trace_category_net)) {
                        basic_stream dbs;
                        dbs.println("+ ACK");
                        trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
                    }
#endif
                }
            }

            // TODO
            // - split
            {
                if (false == get_handshakes().empty()) {
                    binary_t bin;
                    ret = get_handshakes().for_each([&](tls_handshake* handshake) -> return_t {
                        handshake->write(dir, bin);
#if defined DEBUG
                        if (istraceable(trace_category_net)) {
                            basic_stream dbs;
                            dbs.println("+ CRYPTO %s", tlsadvisor->handshake_type_string(handshake->get_type()).c_str());
                            trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
                        }
#endif
                        return success;
                    });

                    auto frame = (quic_frame_crypto*)frame_builder.set(quic_frame_type_crypto).set(packet).build();
                    if (frame) {
                        frame->set(bin, 0);
                    }
                    *packet << frame;
                }
            }

            // padding
            if (get_flags() & quic_pad_packet) {
                // if max_size is set, fill 0 upto max_size
                auto frame = (quic_frame_padding*)frame_builder.set(quic_frame_type_padding).set(packet).build();
                frame->pad(get_payload_size(), quic_pad_packet);
                *packet << frame;
#if defined DEBUG
                if (istraceable(trace_category_net)) {
                    basic_stream dbs;
                    dbs.println("+ PADDING");
                    trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
                }
#endif
            }

            binary_t bin;
            packet->write(dir, bin);
            container.push_back(bin);

            packet->release();
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_packet_publisher::publish(tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        std::set<protection_space_t> spaces;
        probe_spaces(spaces);
        if (spaces.empty()) {
            ret = do_nothing;
            __leave2;
        }

        for (auto space : spaces) {
            std::list<binary_t> container;
            ret = publish_space(space, dir, container);
            if (errorcode_t::success != ret) {
                break;
            }
            for (auto& item : container) {
                func(get_session(), item);
            }
        }
    }
    __finally2 {}
    return ret;
}

bool quic_packet_publisher::is_kindof_initial(tls_handshake* handshake) {
    bool ret = false;
    if (handshake) {
        auto type = handshake->get_type();
        ret = (tls_hs_client_hello == type) || (tls_hs_server_hello == type);
    }
    return ret;
}

bool quic_packet_publisher::is_kindof_handshake(tls_handshake* handshake) {
    bool ret = false;
    if (handshake) {
        auto type = handshake->get_type();
        ret = (tls_hs_client_hello != type) && (tls_hs_server_hello != type);
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
