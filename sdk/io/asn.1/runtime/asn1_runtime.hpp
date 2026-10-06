/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_runtime.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.09.14   Soo Han and Gemini  resolve, is_resolvable
 *
 */

#ifndef __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1RUNTIME__
#define __HOTPLACE_SDK_IO_ASN1_RUNTIME_ASN1RUNTIME__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/types.hpp>
#include <hotplace/sdk/io/parser/lalr1_parser.hpp>
#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace hotplace {
namespace io {

enum class asn1_exports_t {
    list = 0,
    all,
};

struct asn1_exports {
    asn1_exports_t type{asn1_exports_t::list};
    std::vector<std::string> symbols;

    asn1_exports() = default;
    asn1_exports(asn1_exports_t t, const std::vector<std::string>& sym) {
        type = t;
        symbols = sym;
    }
    asn1_exports(asn1_exports_t t, std::vector<std::string>&& sym) {
        type = t;
        symbols = std::move(sym);
    }
    asn1_exports(const asn1_exports& other) { *this = other; }
    asn1_exports(asn1_exports&& other) { *this = std::move(other); }
    asn1_exports& operator=(const asn1_exports& other) {
        type = other.type;
        symbols = other.symbols;
        return *this;
    }
    asn1_exports& operator=(asn1_exports&& other) {
        std::swap(type, other.type);
        symbols = std::move(other.symbols);
        return *this;
    }
    void clear() {
        type = asn1_exports_t::list;
        symbols.clear();
    }
    bool operator==(const asn1_exports& other) const { return (type == other.type) && (symbols == other.symbols); }
};
struct asn1_symbol_module {
    std::string outer_module;
    std::vector<std::string> symbols;

    asn1_symbol_module() = default;
    asn1_symbol_module(const std::string m, const std::vector<std::string>& sym) {
        outer_module = m;
        symbols = sym;
    }
    asn1_symbol_module(const asn1_symbol_module& other) { *this = other; }
    asn1_symbol_module(asn1_symbol_module&& other) { *this = std::move(other); }
    asn1_symbol_module& operator=(const asn1_symbol_module& other) {
        outer_module = other.outer_module;
        symbols = other.symbols;
        return *this;
    }
    asn1_symbol_module& operator=(asn1_symbol_module&& other) {
        outer_module = std::move(other.outer_module);
        symbols = std::move(other.symbols);
        return *this;
    }
    bool operator==(const asn1_symbol_module& other) const { return (outer_module == other.outer_module) && (symbols == other.symbols); }
};

class asn1_runtime {
    friend class asn1_weakly_typed;

   public:
    asn1_runtime();
    asn1_runtime(const std::string& name);
    asn1_runtime(const asn1_runtime& other);
    asn1_runtime(asn1_runtime&& other);
    virtual ~asn1_runtime();

    asn1_runtime& operator=(const asn1_runtime& other);
    asn1_runtime& operator=(asn1_runtime&& other);

    asn1_runtime* clone();

    return_t add_schema(const std::string& schema);
    return_t add(asn1_object* item);
    template <typename F>  // void(asn1_object*)
    asn1_runtime& add(asn1_object* item, F&& f = nullptr) {
        if (item) {
            if (f) std::forward<F>(f)(item);
            add(item);
        }
        return *this;
    }
    asn1_runtime& operator<<(const std::string& schema);
    asn1_runtime& operator<<(asn1_object* item);

    return_t set(asn1_object* item, asn1_value* value);
    asn1_object* get(const std::string& name) const;
    asn1_value* get(asn1_object* item) const;

    /**
     * @brief   weakly-typed (schema-less)
     * @sample
     *          asn1_runtime runtime;
     *          asn1_weakly_typed weaktype;
     *          size_t pos = 0;
     *          weaktype.read_weakly_typed(&runtime, stream, size, pos);
     */
    return_t read_weakly_typed(const byte_t* stream, size_t size, size_t& pos);

    /**
     * @brief   strongly-typed
     * @sample
     *          const char* schema1 = "Type1 ::= VisibleString";
     *          asn1_object* type1 = asn1_referenced_type::define("type1", new asn1_visiblestring);
     *          const char* schema2 = "Type2 ::= [APPLICATION 3] IMPLICIT Type1";
     *          asn1_object* type2 = asn1_referenced_type::define("type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit,
     * asn1_referenced_type::refer("type1"))); const char* schema3 = "Type3 ::= [2] EXPLICIT Type2"; asn1_object* type3 = asn1_referenced_type::define("type3", new
     * asn1_tagged_type(asn1_class_context, 2, asn1_explicit, asn1_referenced_type::refer("type2")));
     *
     *          asn1_runtime runtime;
     *          runtime.add_schema(schema1);
     *          runtime.add_schema(schema2);
     *          runtime.add_schema(schema3);
     *
     *          const char* bytestream = "A2 07 43 05 4A 6F 6E 65 73";
     *          binary_t bin_stream = base16_decode_rfc(bytestream);
     *          auto stream = bin_stream.data();
     *          auto size = bin_stream.size();
     *          size_t pos = 0;
     *          runtime.read("type3", stream, size, pos);
     */
    return_t read(const std::string& name, const byte_t* stream, size_t size, size_t& pos);

    void for_each(std::function<void(asn1_object*)> f) const;
    void for_each(std::function<void(asn1_value*)> f) const;
    void represent(stream_t* s);
    void publish(stream_t* s);
    void publish(binary_t* b);
    void represent(const std::string& name, stream_t* s);
    void publish(const std::string& name, stream_t* s);
    void publish(const std::string& name, binary_t* b);

    /**
     * search dictionary or imports table
     */
    asn1_object* search(const std::string& name) const;
    /**
     * @brief   resolves dependencies starting from a specific root type name.
     */
    bool resolve(const std::string& name, std::list<std::string>& names) const;
    /**
     * @brief   resolves dependencies for all types registered in the dictionary.
     */
    bool resolve(std::list<std::string>& names) const;

    bool is_resolvable(const std::string& name) const;
    bool is_resolvable(asn1_object* object) const;
    /**
     * check if all references in dictionary
     */
    bool is_resolvable() const;

    /**
     * propagation constructed bit (EXPLICIT) and replace reference
     */
    return_t update_linkage(asn1_object* object);

    void set_name(const std::string& name);
    std::string get_name();

    /**
     * - module-level
     *   - MyModule DEFINITIONS ::= BEGIN ...                -- EXPLICIT
     *   - MyModule DEFINITIONS IMPLICIT TAGS ::= BEGIN ...  -- IMPLICIT
     *   - MyModule DEFINITIONS EXPLICIT TAGS ::= BEGIN ...  -- EXPLICIT
     *   - MyModule DEFINITIONS AUTOMATIC TAGS ::= BEGIN ... -- IMPLICIT, [0], [1], ...
     *
     * - CHOICE, ANY MUST be EXPLICIT
     */
    void set_tagdefault(uint8 value);
    uint8 get_tagdefault();
    /**
     * @remarks
     *  The EXTENSIBILITY IMPLIED syntax is a setting that causes the compiler
     *  to implicitly treat all extensible structures defined within a module
     *  as having the specified attribute, even if it is not explicitly written.
     */
    void set_extensibility(uint8 value);
    uint8 get_extensibility();

    asn1_runtime& as_module();
    bool is_module() const;

    asn1_runtime& export_symbol(const asn1_exports& exports);
    asn1_runtime& export_symbol(asn1_exports&& exports);
    asn1_runtime& import_symbol(const asn1_symbol_module& symbol_module);
    asn1_runtime& import_symbol(asn1_symbol_module&& symbol_module);
    const asn1_exports& get_exports() const;
    const std::list<asn1_symbol_module>& get_imports() const;

    void clear();

    void addref();
    void release();

   protected:
    return_t postread(const byte_t* stream, size_t size);

   private:
    t_shared_reference<asn1_runtime> _shared;

    mutable critical_section _lock;
    std::unordered_map<std::string, asn1_object*> _dictionary;

    std::list<asn1_object*> _types;
    std::map<asn1_object*, asn1_value*> _values;
    std::map<asn1_object*, std::string> _schema;  // strongly-typed
    std::string _name;
    uint8 _tagdefault{asn1_explicit};
    uint8 _extensibility{uint8(asn1_extensibility_t::none)};
    bool _is_module{false};

    asn1_exports _exports;
    std::list<asn1_symbol_module> _imports;
};

}  // namespace io
}  // namespace hotplace

#endif
