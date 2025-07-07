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
 *
 */

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORVISITOR__
#define __HOTPLACE_SDK_IO_CBOR_CBORVISITOR__

#include <deque>
#include <sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace io {

class cbor_visitor {
   public:
    virtual return_t visit(cbor_object* object) = 0;
};

/*
 * @brief concise
 * @sa cbor_publisher
 */
class cbor_concise_visitor : public cbor_visitor {
   public:
    cbor_concise_visitor(binary_t* concise);
    virtual ~cbor_concise_visitor();
    virtual return_t visit(cbor_object* object);

    binary_t* get_binary();

   private:
    binary_t* _concise;
};

/*
 * @brief diagnostic
 * @sa cbor_publisher
 */
class cbor_diagnostic_visitor : public cbor_visitor {
   public:
    cbor_diagnostic_visitor(stream_t* stream);
    virtual ~cbor_diagnostic_visitor();
    virtual return_t visit(cbor_object* object);

    stream_t* get_stream();

   private:
    stream_t* _diagnostic;
};

}  // namespace io
}  // namespace hotplace

#endif
