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
#include <sdk/base/stream/segmentation.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/http/http3/http3_frame_builder.hpp>
#include <sdk/net/http/http3/types.hpp>
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

quic_packet_publisher::quic_packet_publisher() : _session(nullptr), _payload_size(0), _flags(0), _streamid(0), _unitype(0) {}

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

quic_packet_publisher& quic_packet_publisher::set_streaminfo(uint64 streamid, uint8 unitype) {
    _streamid = streamid;
    _unitype = unitype;
    return *this;
}

tls_session* quic_packet_publisher::get_session() { return _session; }

uint16 quic_packet_publisher::get_payload_size() { return _payload_size; }

uint32 quic_packet_publisher::get_flags() { return _flags; }

uint64 quic_packet_publisher::get_streamid() { return _streamid; }

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
                auto& pkns = session->get_quic_session().get_pkns(space);
                critical_section_guard guard(pkns.get_lock());
                if (pkns.is_modified()) {
                    spaces.insert(space);
                }
                return success;
            };

            lambda_ack(get_session(), protection_initial);
            lambda_ack(get_session(), protection_handshake);
            lambda_ack(get_session(), protection_application);
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_packet_publisher::publish_space(protection_space_t space, tls_direction_t dir, uint32 flags, std::list<binary_t>& container) {
    return_t ret = errorcode_t::success;
    __try2 {
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

        segmentation segment(get_payload_size());
        binary_t unfragmented;
        if (protection_application == space) {
            if (false == get_frames().empty()) {
                get_frames().for_each([&](http3_frame* frame) -> return_t { return frame->write(unfragmented); });
                segment.assign(quic_frame_type_stream, unfragmented.empty() ? nullptr : &unfragmented[0], unfragmented.size());
            }
        } else {
            if (false == get_handshakes().empty()) {
                get_handshakes().for_each([&](tls_handshake* handshake) -> return_t { return handshake->write(dir, unfragmented); });
                segment.assign(quic_frame_type_crypto, unfragmented.empty() ? nullptr : &unfragmented[0], unfragmented.size());
            }
        }

        binary_t bin;
        size_t concat = 0;

        if (false == container.empty()) {
            auto iter = container.begin();
            std::advance(iter, container.size() - 1);
            if (get_payload_size() != (*iter).size()) {
                bin = std::move(*iter);
                concat = bin.size();
                container.erase(iter);
            }
        }

        do {
            auto packet = packet_builder.set(type).set(session).set(&segment, concat).set(dir).construct().build();
            if (packet) {
#if defined DEBUG
                if (istraceable(trace_category_net, loglevel_debug)) {
                    basic_stream dbs;
                    dbs.println("\e[1;32mPKN %i length %i\e[0m", packet->get_pn(), packet->get_pn_length());
                    trace_debug_event(trace_category_net, trace_event_quic_packet, &dbs);
                }
#endif

                // ack
                if (quic_ack_packet & flags) {
                    auto& pkns = session->get_quic_session().get_pkns(space);
                    critical_section_guard guard(pkns.get_lock());
                    if (pkns.is_modified()) {
                        auto frame = (quic_frame_ack*)frame_builder.set(quic_frame_type_ack).set(packet).build();
                        frame->set_protection_level(space);
                        *packet << frame;
                    }
                }

                if (false == unfragmented.empty()) {
                    if (protection_application == space) {
                        auto frame = (quic_frame_stream*)frame_builder.set(quic_frame_type_stream).set(packet).set_streaminfo(_streamid, _unitype).build();
                        *packet << frame;
                    } else {
                        auto frame = (quic_frame_crypto*)frame_builder.set(quic_frame_type_crypto).set(packet).build();
                        *packet << frame;
                    }
                }

                // padding
                if (flags & quic_pad_packet) {
                    // if max_size is set, fill 0 upto max_size
                    auto frame = (quic_frame_padding*)frame_builder.set(quic_frame_type_padding).set(packet).build();
                    frame->pad(get_payload_size(), quic_pad_packet);
                    *packet << frame;
                }

                packet->write(dir, bin);
                container.push_back(std::move(bin));

                packet->release();
            }
        } while (success == segment.isready());
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

        std::list<binary_t> container;
        for (auto space : spaces) {
            uint32 flags = get_flags();
            if (spaces.size() > 1) {
                if (*spaces.rbegin() != space) {
                    flags &= ~quic_pad_packet;
                }
            }
            ret = publish_space(space, dir, flags, container);
            if (errorcode_t::success != ret) {
                break;
            }
        }
        for (auto& item : container) {
            func(get_session(), item);
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
