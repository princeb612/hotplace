/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_publisher.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1PUBLISHER__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1PUBLISHER__

#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/types.hpp>
#include <hotplace/sdk/io/asn.1/runtime/types.hpp>
#include <hotplace/sdk/io/parser/types.hpp>
#include <stack>
#include <unordered_map>

namespace hotplace {
namespace io {

struct asn1_semantic_node {
    std::string symbol;
    std::string value;
    asn1_object* object;

    asn1_semantic_node() : object(nullptr) {}
    ~asn1_semantic_node() {
        if (object) object->release();
    }

    asn1_semantic_node(const asn1_semantic_node& other) : asn1_semantic_node() { *this = other; }
    asn1_semantic_node& operator=(const asn1_semantic_node& other) {
        symbol = other.symbol;
        value = other.value;
        if (other.object) other.object->addref();  // shallow copy
        object = other.object;
        return *this;
    }
    asn1_semantic_node(asn1_semantic_node&& other) : asn1_semantic_node() { *this = std::move(other); }
    asn1_semantic_node& operator=(asn1_semantic_node&& other) {
        symbol = std::move(other.symbol);
        value = std::move(other.value);
        std::swap(object, other.object);
        return *this;
    }

    asn1_object* get() const { return object; }
    void release() { object = nullptr; }  // releases the ownership
};

class asn1_publisher_context {
   public:
    asn1_publisher_context() = default;
    ~asn1_publisher_context() = default;

    void push(const asn1_semantic_node& node) { _stack.push(node); }
    void push(asn1_semantic_node&& node) { _stack.push(std::move(node)); }
    asn1_semantic_node& top() { return _stack.top(); }
    asn1_semantic_node pop() {
        asn1_semantic_node node;
        if (false == _stack.empty()) {
            node = std::move(_stack.top());
            _stack.pop();
        }
        return node;
    }
    size_t size() const { return _stack.size(); }
    bool empty() const { return _stack.empty(); }

   private:
    std::stack<asn1_semantic_node> _stack;
};

class asn1_publisher {
   public:
    asn1_publisher();
    ~asn1_publisher();

    return_t build(const parse_tree* pt, asn1_object** object);

    using handler_t = std::function<return_t(parse_treenode*, asn1_publisher_context&)>;

    template <typename F>
    void add_handler(const std::string& name, F&& handler) {
        if (false == name.empty()) {
            _handler_map[name] = std::forward<F>(handler);
        }
    }

   protected:
    void prepare();
    return_t default_handler(parse_treenode* node, asn1_publisher_context& st);

   private:
    std::unordered_map<std::string, handler_t> _handler_map;
};

}  // namespace io
}  // namespace hotplace

#endif
