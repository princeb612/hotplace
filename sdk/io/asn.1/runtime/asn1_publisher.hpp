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

#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint.hpp>
#include <hotplace/sdk/io/asn.1/basic/types.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/asn.1/runtime/types.hpp>
#include <hotplace/sdk/io/parser/types.hpp>
#include <stack>
#include <unordered_map>

namespace hotplace {
namespace io {

struct asn1_semantic_node {
    // parse_tree
    std::string symbol;
    std::string value;

    // module
    struct moduledefault {
        asn1_taggingmode_t tagdefault{asn1_tagdefault};
        asn1_extensibility_t extensibility{asn1_extensibility_t::none};

        moduledefault() = default;
        moduledefault(const moduledefault& other) { *this = other; }
        moduledefault(moduledefault&& other) { *this = std::move(other); }
        moduledefault& operator=(const moduledefault& other) {
            tagdefault = other.tagdefault;
            extensibility = other.extensibility;
            return *this;
        }
        moduledefault& operator=(moduledefault&& other) {
            std::swap(tagdefault, other.tagdefault);
            std::swap(extensibility, other.extensibility);
            return *this;
        }
    } module;

    // asn1_object*
    asn1_object* object{nullptr};
    asn1_option option;

    // constraints
    variant v;
    variant v_to;
    type_category_t cons_type{type_category_t::unknown};
    union {
        asn1_constraint_t* u;
        asn1_constraint<asn1_native_int_t>* i;
        asn1_constraint<double>* f;
        asn1_constraint<std::string>* s;
    } cons;

    asn1_semantic_node() { cons.u = nullptr; }
    ~asn1_semantic_node() {
        if (object) object->release();
        if (cons.u) cons.u->release();
    }

    asn1_semantic_node(const asn1_semantic_node& other) : asn1_semantic_node() { *this = other; }
    asn1_semantic_node& operator=(const asn1_semantic_node& other) {
        symbol = other.symbol;
        value = other.value;
        module = other.module;
        if (other.object) other.object->addref();  // shallow copy
        object = other.object;
        option = other.option;
        v = other.v;
        v_to = other.v_to;
        cons_type = other.cons_type;
        if (other.cons.u) other.cons.u->addref();
        cons.u = other.cons.u;
        return *this;
    }
    asn1_semantic_node(asn1_semantic_node&& other) : asn1_semantic_node() { *this = std::move(other); }
    asn1_semantic_node& operator=(asn1_semantic_node&& other) {
        symbol = std::move(other.symbol);
        value = std::move(other.value);
        module = std::move(other.module);
        std::swap(object, other.object);
        option = std::move(other.option);
        v = std::move(other.v);
        v_to = std::move(other.v_to);
        std::swap(cons_type, other.cons_type);
        std::swap(cons, other.cons);
        return *this;
    }

    asn1_object* get() const { return object; }
    // releases the ownership
    void release() {
        object = nullptr;
        option.release();
        cons.u = nullptr;
    }
    asn1_semantic_node& release_object() {
        object = nullptr;
        return *this;
    }
    asn1_semantic_node& release_option() {
        option.release();
        return *this;
    }
    asn1_semantic_node& release_constraint() {
        cons.u = nullptr;
        return *this;
    }
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

    asn1_runtime& get_runtime() { return _runtime; };
    std::vector<std::string>& get_symbols() { return _symbols; }

   private:
    std::stack<asn1_semantic_node> _stack;
    asn1_runtime _runtime;              // ModuleDefinition, TypeAssignment
    std::vector<std::string> _symbols;  // SymbolList
};

/**
 * @comments
 *          auto publisher = asn1_advisor::get_instance()->get_publisher();
 *          publisher->parse(pt, result);
 */
class asn1_publisher {
    friend class asn1_advisor;

   public:
    ~asn1_publisher();

    /**
     * @brief   build
     * @param   const parse_tree* pt [in] pointer of parse tree
     * @param   asn1_build_resultset& result [out] unified result container
     * @remarks
     *          - Module definition:
     *              Result type set to `module_definition`.
     *              Module names populated in `result.module_names`.
     *              Accessible via `asn1_runtime_context::get_instance()`.
     *
     *          - No module definition and assignment:
     *              Result type set to `assignments`.
     *              Temporary runtime generated with Base16 timestamp key.
     *              Stored in `result.runtime`.
     *
     *          - Non-assignment:
     *              Result type set to `non_assignment`.
     *              Semantic object stored in `result.object`.
     */
    return_t build(const parse_tree* pt, asn1_build_resultset& result);

    // function pointer
    using handler_t = return_t (*)(parse_treenode*, asn1_publisher_context&, asn1_build_resultset&);

    void add_handler(const std::string& name, handler_t handler);

    bool prepare();
    bool ready() const;

   protected:
    asn1_publisher();

    return_t default_handler(parse_treenode* node, asn1_publisher_context& st, asn1_build_resultset& result);

    uint16 make_key(parser_t* parser);

   private:
    mutable critical_section _lock;
    std::unordered_map<std::string, handler_t> _handler_map;
    // std::unordered_map<uint32, std::vector<handler_t>> _handler_flat_map;
    bool _ready;

    /**
     * @brief   notation
     * @sa      add_hander
     */
    void prepare_basics();
    /**
     * @brief   constraints
     * @sa      add_hander
     */
    void prepare_constraints();
};

}  // namespace io
}  // namespace hotplace

#endif
