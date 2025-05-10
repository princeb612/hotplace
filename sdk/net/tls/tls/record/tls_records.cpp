/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * Revision History
 * Date         Name                Description
 */

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

        while (pos < size) {
            uint8 content_type = stream[pos];
            tls_record_builder builder;
            auto record = builder.set(session).set(content_type).build();
            if (record) {
                ret = record->read(dir, stream, size, pos);
                if (errorcode_t::success == ret) {
                    add(record);
                } else {
                    record->release();
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

return_t tls_records::write(tls_session* session, tls_direction_t dir, std::function<void(binary_t& bin)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);
        if (session_dtls == session->get_type()) {
            // fragmentation
            session->get_dtls_record_publisher().publish(this, dir, func);
        } else {
            binary_t bin;
            auto lambda = [&](tls_record* record) -> return_t { return record->write(dir, bin); };
            ret = for_each(lambda);
            func(bin);
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
