/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   parser_resource.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026-08-29   Soo Han and Gemini  study
 */

#ifndef __HOTPLACE_SDK_IO_PARSER_PARSERRESOURCE__
#define __HOTPLACE_SDK_IO_PARSER_PARSERRESOURCE__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <hotplace/sdk/io/parser/types.hpp>

namespace hotplace {
namespace io {

struct parser_token_resource {
    uint32 token;
    const char* name;
};

extern const parser_token_resource parser_symbol_tokens[];
extern const size_t sizeof_parser_symbol_tokens;
extern const parser_token_resource parser_basic_tokens[];
extern const size_t sizeof_parser_basic_tokens;

class parser_resource {
   public:
    static parser_resource* get_instance();

    std::string nameof(uint32 token) const;

    template <typename F>
    void for_each(resource_type_t type, F&& func) const {
        const parser_token_resource* array = nullptr;
        size_t size = 0;
        if (resource_type_t::token_type_symbol == type) {
            array = parser_symbol_tokens;
            size = sizeof_parser_symbol_tokens;
            if (resource_type_t::token_type_basic == type) {
                array = parser_basic_tokens;
                size = sizeof_parser_basic_tokens;
            }
            for (size_t i = 0; i < size; ++i) {
                const auto& item = array[i];
                std::forward<F>(func)(item.token, item.name);
            }
        }
    }

   protected:
    parser_resource();

    void load();
    void load_basic_tokens();

   private:
    mutable critical_section _lock;
    static parser_resource _instance;

    std::map<uint32, std::string> _token_names;  // token name
};

}  // namespace io
}  // namespace hotplace

#endif
