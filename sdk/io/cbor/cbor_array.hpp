/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORARRAY__
#define __HOTPLACE_SDK_IO_CBOR_CBORARRAY__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/cbor/cbor_object.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <deque>

namespace hotplace {
namespace io {

/*
 * @brief   array type
 * @example
 *          cbor_array* array = new cbor_array ();
 *          *array  << (new cbor_pair ("item1", new cbor_data ("value1")))
 *                  << (new cbor_pair ("item2", new cbor_data (12345)))
 *                  << (new cbor_pair ("item3", new cbor_data (true)))
 *                  << (new cbor_pair ("item4", new cbor_data (1.2345)))
 *                  << (new cbor_pair ("item5", new cbor_pair ("subitem1", new cbor_data ("subvalue1"))))
 *                  << (new cbor_pair ("item6", new cbor_data (true)))
 *                  << (new cbor_pair ("item7", new cbor_data ()));
 *          // ...
 *          array->release ();
 */
class cbor_array : public cbor_object
{
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;
public:
    cbor_array ();
    cbor_array (uint32 flags);
    virtual ~cbor_array ();

    /*
     * @brief   add
     * @param   cbor_object* object [in]
     * @param   cbor_object* extra [inopt] ignored
     * @return  error code (see error.hpp)
     */
    virtual return_t join (cbor_object* object, cbor_object* extra = nullptr);

    cbor_array& add (cbor_array* object);
    cbor_array& add (cbor_data* object);
    cbor_array& add (cbor_map* object);

    cbor_array& operator << (cbor_array* object);
    cbor_array& operator << (cbor_data* object);
    cbor_array& operator << (cbor_map* object);

    virtual size_t size ();
    cbor_object const* operator [] (size_t index);
    std::list <cbor_object*> const& accessor ();

    virtual int addref ();
    virtual int release ();

protected:

    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

private:
    std::list <cbor_object*> _array;
};

}
}  // namespace

#endif
