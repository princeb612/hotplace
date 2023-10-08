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

#ifndef __HOTPLACE_SDK_IO_CBOR_CBOROBJECT__
#define __HOTPLACE_SDK_IO_CBOR_CBOROBJECT__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/cbor/concise_binary_object_representation.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <deque>

namespace hotplace {
namespace io {

class cbor_object;
class cbor_data;
class cbor_bstrings;
class cbor_tstrings;
class cbor_pair;
class cbor_map;
class cbor_array;
class cbor_visitor;

/*
 *  cbor_object
 *  \_ cbor_data
 *     - variant_t
 *  \_ cbor_bstrings
 *     - list <cbor_data*>
 *  \_ cbor_tstrings
 *     - list <cbor_data*>
 *  \_ cbor_pair
 *     - cbor_data*, cbor_object*
 *  \_ cbor_map
 *     - map <cbor_pair*>
 *  \_ cbor_array
 *     - list <cbor_object*>
 */
class cbor_object
{
    friend class cbor_array;
    friend class cbor_pair;
    friend class cbor_encode;
    friend class cbor_publisher;
    friend class cbor_reader;
    friend class cbor_concise_visitor;
    friend class cbor_diagnostic_visitor;
public:
    cbor_object ();
    cbor_object (cbor_type_t type, uint32 flags = 0);
    virtual ~cbor_object ();

    /*
     * @brief   add
     * @param   cbor_object* object [in]
     * @param   cbor_object* extra [inopt] ignored
     * @return  error code (see error.hpp)
     * @sa      check cbor_map::join
     */
    virtual return_t join (cbor_object* object, cbor_object* extra = nullptr);
    cbor_object& add (cbor_object* object, cbor_object* extra = nullptr);

    cbor_type_t type ();
    virtual size_t size ();
    uint32 get_flags ();

    void tag (bool use, cbor_tag_t tag);
    bool tagged ();
    cbor_tag_t tag_value ();

    virtual int addref ();
    virtual int release ();

protected:
    void reserve (size_t size); ///<< reserve a capacity while parsing
    size_t capacity ();         ///<< reserved size

    virtual void accept (cbor_visitor* v);
    virtual void represent (stream_t* s);
    virtual void represent (binary_t* b);

    t_shared_reference <cbor_object>  _shared;

private:
    cbor_type_t _type;
    uint32 _flags;
    bool _tagged; ///<< addtitional flag (cbor_tag_t::std_datetime is 0)
    cbor_tag_t _tag;
    uint64 _reserved_size;
};

}
}  // namespace

#endif
