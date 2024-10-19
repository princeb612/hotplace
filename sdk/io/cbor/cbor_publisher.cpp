/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_visitor.hpp>

namespace hotplace {
namespace io {

cbor_publisher::cbor_publisher() {
    // do nothing
}

return_t cbor_publisher::publish(cbor_object* object, binary_t* b) {
    // 8.  Diagnostic Notation
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object || nullptr == b) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        b->clear();

        cbor_concise_visitor concise(b);
        object->accept(&concise);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t cbor_publisher::publish(cbor_reader_context_t* handle, binary_t* b) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == b) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        b->clear();

        auto lambda = [](unsigned int idx, cbor_object* object, binary_t* b) -> void {
            cbor_concise_visitor concise(b);
            object->accept(&concise);
        };

        cbor_reader reader;
        reader.cbor_foreach(handle, lambda, b);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t cbor_publisher::publish(cbor_object* object, stream_t* s) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == object || nullptr == s) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        s->clear();

        cbor_diagnostic_visitor diagnostic(s);
        object->accept(&diagnostic);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t cbor_publisher::publish(cbor_reader_context_t* handle, stream_t* s) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == s) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        s->clear();

        auto lambda = [](unsigned int idx, cbor_object* object, stream_t* s) -> void {
            if (idx) {
                s->printf(",");
            }
            cbor_diagnostic_visitor diagnostic(s);
            object->accept(&diagnostic);
        };

        cbor_reader reader;
        reader.cbor_foreach(handle, lambda, s);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace io
}  // namespace hotplace
