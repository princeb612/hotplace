/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_node.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_BASIC_STRUCTURAL_ASN1NODE__
#define __HOTPLACE_SDK_IO_ASN1_BASIC_STRUCTURAL_ASN1NODE__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/types.hpp>

namespace hotplace {
namespace io {

class asn1_node {
   public:
    asn1_node(const asn1_node& other);
    virtual ~asn1_node();

    asn1_node& operator=(const asn1_node& other);
    virtual asn1_node* clone();

    virtual bool is_leaf() const;
    void set_parent(asn1_node* parent);
    asn1_node* get_parent();
    void set_name(const std::string& name);
    const std::string& get_name() const;
    uint8 get_identifier() const;
    uint64 get_tag() const;
    uint64 get_len() const;

    asn1_node& add(asn1_node* child);
    asn1_node& operator<<(asn1_node* child);

    void clear();

    void for_each(std::function<void(asn1_node*)> f) const;
    size_t size() const;

    void addref();
    void release();

   protected:
    asn1_node(uint8 identifier, uint64 tag, uint64 len);
    virtual bool is_container();

   private:
    asn1_node* _parent;
    std::string _name;
    uint8 _identifier;
    uint64 _tag;
    uint64 _len;
    std::list<asn1_node*> _children;
    t_shared_reference<asn1_node> _shared;
};

}  // namespace io
}  // namespace hotplace

#endif
