/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/dtls_record_publisher.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_records.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_records::tls_records() {}

tls_records::~tls_records() { clear(); }

return_t tls_records::read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto lambda = [](tls_records* records, tls_session* sess, tls_direction_t sdir, const byte_t* sstream, size_t ssize, size_t& spos) -> return_t {
            return_t ret = errorcode_t::success;
            uint8 content_type = sstream[spos];
            tls_record_builder builder;
            auto record = builder.set(sess).set(content_type).build();
            if (record) {
                ret = record->read(sdir, sstream, ssize, spos);
                if (errorcode_t::success == ret) {
                    records->add(record);
                } else {
                    record->release();
                }
            } else {
                ret = errorcode_t::internal_error;
            }
            return ret;
        };

        while (pos < size) {
            // condition TCP segmentation
            auto& secrets = session->get_tls_protection().get_secrets();
            const binary_t& segment = secrets.get(tls_context_segment);
            auto segmentsize = segment.size();
            if (segmentsize) {
                // reassemble
                tls_header* header = (tls_header*)(&segment[0]);
                uint16 len = ntoh16(header->length);
                auto reassemblesize = sizeof(tls_header) + len;

                size_t spos = pos;
                auto avail = size - pos;
                auto necessary = reassemblesize - segmentsize;
                pos += avail;

                if (necessary) {
                    secrets.append(tls_context_segment, stream + spos, avail);

                    bool reassembled = (avail >= necessary) ? true : false;
                    if (false == reassembled) {
                        break;  // do not read
                    }
                }

                size_t tpos = 0;
                auto test = lambda(this, session, dir, &segment[0], segment.size(), tpos);
            } else {
                auto test = lambda(this, session, dir, stream, size, pos);
                if (errorcode_t::success == test) {
                } else if (errorcode_t::block_segmented == test) {
                    continue;
                } else {
                    ret = test;
                    break;
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_records::read(tls_session* session, tls_direction_t dir, const binary_t& bin) {
    const byte_t* stream = &bin[0];
    size_t size = bin.size();
    size_t pos = 0;
    return read(session, dir, stream, size, pos);
}

return_t tls_records::write(tls_session* session, tls_direction_t dir, std::function<void(tls_session*, binary_t& bin)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);
        if (session_type_dtls == session->get_type()) {
            // fragmentation
            session->get_dtls_record_publisher().publish(this, dir, func);
        } else {
            binary_t bin;
            auto lambda = [&](tls_record* record) -> return_t { return record->write(dir, bin); };
            ret = for_each(lambda);
            func(session, bin);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_records::add(tls_record* record, bool upref) {
    return_t ret = errorcode_t::success;
    if (record) {
        if (upref) {
            record->addref();
        }

        critical_section_guard guard(_lock);

        auto type = record->get_type();
        _records.push_back(record);
    }
    return ret;
}

tls_records& tls_records::operator<<(tls_record* record) {
    add(record);
    return *this;
}

return_t tls_records::for_each(std::function<return_t(tls_record*)> func) {
    return_t ret = errorcode_t::success;
    if (func) {
        critical_section_guard guard(_lock);
        for (auto item : _records) {
            ret = func(item);
            if (errorcode_t::success != ret) {
                break;
            }
        }
    }
    return ret;
}

tls_record* tls_records::getat(size_t index, bool upref) const {
    tls_record* obj = nullptr;
    if (index < _records.size()) {
        obj = _records[index];
    }
    return obj;
}

size_t tls_records::size() { return _records.size(); }

void tls_records::clear() {
    critical_section_guard guard(_lock);
    for (auto record : _records) {
        record->release();
    }
    _records.clear();
}

}  // namespace net
}  // namespace hotplace
