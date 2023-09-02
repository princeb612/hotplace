/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace io {

cbor_object::cbor_object () : _type (cbor_type_t::cbor_type_null), _flags (0), _tagged (false), _tag (cbor_tag_t (0)), _reserved_size (0)
{
    _shared.make_share (this);
}

cbor_object::cbor_object (cbor_type_t type, uint32 flags) : _type (type), _flags (flags), _tagged (false), _tag (cbor_tag_t (0)), _reserved_size (0)
{
    addref ();
}

cbor_object::~cbor_object ()
{
    // do nothing
}

cbor_type_t cbor_object::type ()
{
    return _type;
}

size_t cbor_object::size ()
{
    return 1;
}

uint32 cbor_object::get_flags ()
{
    return _flags;
}

return_t cbor_object::join (cbor_object* object, cbor_object* extra)
{
    return errorcode_t::not_available;
}

void cbor_object::tag (bool use, cbor_tag_t tag)
{
    _tagged = use;
    _tag = tag;
}

bool cbor_object::tagged ()
{
    return _tagged;
}

cbor_tag_t cbor_object::tag_value ()
{
    return _tag;
}

void cbor_object::reserve (size_t size)
{
    _reserved_size = size;
}

size_t cbor_object::reserved_size ()
{
    return _reserved_size;
}

int cbor_object::addref ()
{
    return _shared.addref ();
}

int cbor_object::release ()
{
    return _shared.delref ();
}

void cbor_object::accept (cbor_visitor* v)
{
    v->visit (this);
}

void cbor_object::represent (stream_t* s)
{
    // do nothing
}

void cbor_object::represent (binary_t* b)
{
    // do nothing
}

}
}
