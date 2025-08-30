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
                    break;
                }
            }
        }
    }
    __finally2 {}
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
    __finally2 {}
    return ret;
}

return_t tls_records::add(tls_record* record, bool upref) { return _records.add(record, upref); }

tls_records& tls_records::operator<<(tls_record* record) {
    add(record);
    return *this;
}

return_t tls_records::for_each(std::function<return_t(tls_record*)> func) { return _records.for_each(func); }

tls_record* tls_records::getat(size_t index, bool upref) { return _records.getat(index, upref); }

bool tls_records::empty() { return _records.empty(); }

size_t tls_records::size() { return _records.size(); }

void tls_records::clear() { _records.clear(); }

}  // namespace net
}  // namespace hotplace
