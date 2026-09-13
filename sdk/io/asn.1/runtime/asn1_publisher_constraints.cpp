/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_publisher_constraints.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *
 */

#include <hotplace/sdk/base/nostd/atoi.hpp>
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/asn1_object.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_all_except.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_container.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_except.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_from.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_intersection.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_pattern.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_range.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_single_value.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_size.hpp>
#include <hotplace/sdk/io/asn.1/basic/semantic/constraints/asn1_constraint_union.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_builder.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>
#include <string>

namespace hotplace {
namespace io {

void asn1_publisher::prepare_constraints() {
    auto resource = asn1_resource::get_instance();

    add_handler("Constraint", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("Constraint", {"(", "ConstraintExpr", ")"})

        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        asn1_semantic_node asn;
        asn.symbol = node->symbol;
        if (3 == size) {
            asn.cons.u = rhs[1].cons.u;
            rhs[1].release();
        }

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("ConstraintExpr", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("ConstraintExpr", {"SubtypeElementSet"})
        // production("ConstraintExpr", {"ALL EXCEPT", "SubtypeElementSet"})
        // production("ConstraintExpr", {"ALL", "EXCEPT", "SubtypeElementSet"})

        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        asn1_semantic_node asn;
        asn.symbol = node->symbol;

        if (1 == size) {
            asn.cons = rhs[0].cons;
            rhs[0].release();
        } else {
            auto next = (3 == size) ? 2 : 1;
            auto type = rhs[next].cons.u->type();
            asn1_constraint_t* cons = nullptr;

            if (type_category_t::integral == type) {
                cons = new asn1_constraint_all_except_i(rhs[next].cons.i);
            } else if (type_category_t::floating_point == type) {
                cons = new asn1_constraint_all_except_f(rhs[next].cons.f);
            } else if (type_category_t::cstring == type) {
                cons = new asn1_constraint_all_except_s(rhs[next].cons.s);
            } else {
                cons = new asn1_constraint_all_except_f(rhs[next].cons.f);
            }
            asn.cons.u = cons;
            rhs[next].release();
        }

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("SubtypeElementSet", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("SubtypeElementSet", {"SubtypeElementSet", "|", "SubtypeElement"})
        // production("SubtypeElementSet", {"SubtypeElementSet", ",", "SubtypeElement"})
        // production("SubtypeElementSet", {"SubtypeElementSet", "UNION", "SubtypeElement"})
        // production("SubtypeElementSet", {"SubtypeElementSet", "EXCEPT", "SubtypeElement"})
        // production("SubtypeElementSet", {"SubtypeElementSet", "SubtypeElement"})
        // production("SubtypeElementSet", {"SubtypeElement"})

        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        asn1_semantic_node asn;
        asn.symbol = node->symbol;
        if (1 == size) {
            asn.cons = rhs[0].cons;
            rhs[0].release();
        } else if (2 == size) {
            auto cons = new asn1_constraint_container;
            cons->add(rhs[0].cons.u).add(rhs[1].cons.u);
            rhs[0].release();
            rhs[1].release();
            asn.cons.u = cons;
        } else if (3 == size) {
            if (rhs[1].symbol == "|" || rhs[1].symbol == "," || rhs[1].symbol == "UNION") {
                auto type = rhs[2].cons.u->type();
                asn1_constraint_t* cons = nullptr;

                if (type_category_t::integral == type) {
                    cons = new asn1_constraint_union_i(rhs[0].cons.i, rhs[2].cons.i);
                } else if (type_category_t::floating_point == type) {
                    cons = new asn1_constraint_union_f(rhs[0].cons.f, rhs[2].cons.f);
                } else if (type_category_t::cstring == type) {
                    cons = new asn1_constraint_union_s(rhs[0].cons.s, rhs[2].cons.s);
                } else {
                    cons = new asn1_constraint_union_f(rhs[0].cons.f, rhs[2].cons.f);
                }
                asn.cons.u = cons;
                rhs[0].release();
                rhs[2].release();
            } else if (rhs[1].symbol == "EXCEPT") {
                auto type = rhs[2].cons.u->type();
                asn1_constraint_t* cons = nullptr;

                if (type_category_t::integral == type) {
                    cons = new asn1_constraint_except_i(rhs[0].cons.i, rhs[2].cons.i);
                } else if (type_category_t::floating_point == type) {
                    cons = new asn1_constraint_except_f(rhs[0].cons.f, rhs[2].cons.f);
                } else if (type_category_t::cstring == type) {
                    cons = new asn1_constraint_except_s(rhs[0].cons.s, rhs[2].cons.s);
                } else {
                    cons = new asn1_constraint_except_f(rhs[0].cons.f, rhs[2].cons.f);
                }
                asn.cons.u = cons;
                rhs[0].release();
                rhs[2].release();
            }
        }

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("SubtypeElement", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("SubtypeElement", {"SubtypeElement", "^", "PrimaryElement"})
        // production("SubtypeElement", {"SubtypeElement", "INTERSECTION", "PrimaryElement"})
        // production("SubtypeElement", {"PrimaryElement"})

        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        asn1_semantic_node asn;
        asn.symbol = node->symbol;

        if (1 == size) {
            asn.cons = rhs[0].cons;
            rhs[0].release();
        } else if (3 == size) {
            if (rhs[1].symbol == "^" || rhs[1].symbol == "INTERSECTION") {
                auto type = rhs[2].cons.u->type();
                asn1_constraint_t* cons = nullptr;

                if (type_category_t::integral == type) {
                    cons = new asn1_constraint_intersection_i(rhs[0].cons.i, rhs[2].cons.i);
                } else if (type_category_t::floating_point == type) {
                    cons = new asn1_constraint_intersection_f(rhs[0].cons.f, rhs[2].cons.f);
                } else if (type_category_t::cstring == type) {
                    cons = new asn1_constraint_intersection_s(rhs[0].cons.s, rhs[2].cons.s);
                } else {
                    cons = new asn1_constraint_intersection_f(rhs[0].cons.f, rhs[2].cons.f);
                }
                asn.cons.u = cons;
                rhs[0].release();
                rhs[2].release();
            }
        }

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("PrimaryElement", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("PrimaryElement", {"ValueElement"})
        // production("PrimaryElement", {"ValueElement", "..", "ValueElement"})
        // production("PrimaryElement", {"ValueElement", "..", "<", "ValueElement"}) // exclusive range support
        // production("PrimaryElement", {"SIZE", "Constraint"})
        // production("PrimaryElement", {"FROM", "Constraint"})
        // production("PrimaryElement", {"PATTERN", symqs})
        // production("PrimaryElement", {"(", "ConstraintExpr", ")"})

        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        auto& rhs_first = rhs[0];

        asn1_semantic_node asn;
        asn.symbol = node->symbol;

        if ("ValueElement" == rhs_first.symbol) {
            if (1 == size) {
                asn1_constraint_t* cons = nullptr;
                if (rhs_first.v.is_int()) {
                    cons = new asn1_constraint_single_value_i(rhs_first.v.value<int64>());
                } else if (rhs_first.v.is_float()) {
                    cons = new asn1_constraint_single_value_f(rhs_first.v.value<double>());
                } else if (rhs_first.v.is_string()) {
                    cons = new asn1_constraint_single_value_s(rhs_first.v.value<const char*>());
                }
                asn.cons.u = cons;
            } else {
                // ..
                size_t next = (size == 4) ? 3 : 2;
                auto& rhs_second = rhs[next];

                asn1_constraint_t* cons = nullptr;
                if (rhs_first.v.is_int() && rhs_second.v.is_int()) {
                    cons = new asn1_constraint_range_i(rhs_first.v.value<int64>(), rhs_second.v.value<int64>());
                } else if (rhs_first.v.is_float() && rhs_second.v.is_float()) {
                    cons = new asn1_constraint_range_f(rhs_first.v.value<double>(), rhs_second.v.value<double>());
                } else if (rhs_first.v.is_minvalue()) {
                    if (rhs_second.v.is_int()) {
                        cons = new asn1_constraint_range_i(range_type_t::minvalue, rhs_second.v.value<int64>());
                    } else if (rhs_second.v.is_float()) {
                        cons = new asn1_constraint_range_f(range_type_t::minvalue, rhs_second.v.value<double>());
                    } else if (rhs_second.v.is_maxvalue()) {
                        cons = new asn1_constraint_range_f(range_type_t::minvalue, range_type_t::maxvalue);
                    }
                } else if (rhs_second.v.is_maxvalue()) {
                    if (rhs_first.v.is_int()) {
                        cons = new asn1_constraint_range_i(rhs_first.v.value<int64>(), range_type_t::maxvalue);
                    } else if (rhs_first.v.is_float()) {
                        cons = new asn1_constraint_range_f(rhs_first.v.value<double>(), range_type_t::maxvalue);
                    }
                }
                asn.cons.u = cons;
            }
        } else if ("SIZE" == rhs_first.symbol) {
            auto& rhs_second = rhs[1];
            asn1_constraint_t* cons = nullptr;
            if (type_category_t::integral == rhs_second.cons.u->type()) {
                cons = new asn1_constraint_size_i(rhs_second.cons.i);
                rhs_second.release();
            }
            asn.cons.u = cons;
        } else if ("FROM" == rhs_first.symbol) {
            auto& rhs_second = rhs[1];
            asn1_constraint_t* cons = nullptr;
            if (type_category_t::cstring == rhs_second.cons.u->type()) {
                cons = new asn1_constraint_from_s(rhs_second.cons.s);
                rhs_second.release();
            }
            asn.cons.u = cons;
        } else if ("PATTERN" == rhs_first.symbol) {
            auto& rhs_second = rhs[1];
            std::string& qs = rhs_second.value;
            if (false == qs.empty()) qs.erase(qs.begin());
            if (false == qs.empty()) qs.pop_back();

            auto cons = new asn1_constraint_pattern_s(qs);
            rhs_second.release();

            asn.cons.u = cons;
        } else if (1 < size) {
            if ("ConstraintExpr" == rhs[1].symbol) {
                asn.cons = rhs[1].cons;
                rhs[1].release();
            }
        }

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("SizeConstraint", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("SizeConstraint", {"SIZE", "Constraint"})

        auto size = node->sizeof_rhs();
        std::vector<asn1_semantic_node> rhs(size);
        for (size_t i = 0; i < size; ++i) {
            rhs[size - 1 - i] = context.pop();
        }

        asn1_semantic_node asn;
        asn.symbol = node->symbol;

        auto& rhs_second = rhs[1];
        asn1_constraint_t* cons = nullptr;
        if (type_category_t::integral == rhs_second.cons.u->type()) {
            cons = new asn1_constraint_size_i(rhs_second.cons.i);
            rhs_second.release();
        }
        asn.cons.u = cons;

        context.push(std::move(asn));

        return errorcode_t::success;
    });
    add_handler("ValueElement", [resource](parse_treenode* node, asn1_publisher_context& context) -> return_t {
        // production("ValueElement", {symid})
        // production("ValueElement", {symuser})
        // production("ValueElement", {symqs})
        // production("ValueElement", {"MIN"})
        // production("ValueElement", {"MAX"})
        // production("ValueElement", {"TRUE"})
        // production("ValueElement", {"FALSE"})
        // production("ValueElement", {symnum})
        // production("ValueElement", {symfp})

        auto rhs_valueelem = context.pop();

        auto pr = parser_resource::get_instance();
        auto symqs = pr->nameof(token_quot_string);
        auto symnum = pr->nameof(token_number);
        auto symfp = pr->nameof(token_floatingpoint);

        asn1_semantic_node asn;
        asn.symbol = node->symbol;
        if (symqs == rhs_valueelem.symbol) {
            std::string& qs = rhs_valueelem.value;
            if (false == qs.empty()) qs.erase(qs.begin());
            if (false == qs.empty()) qs.pop_back();
            asn.v.set_string(qs);
        } else if (symnum == rhs_valueelem.symbol) {
            asn.v.set(t_atoi<asn1_native_int_t>(rhs_valueelem.value));
        } else if (symfp == rhs_valueelem.symbol) {
            asn.v.set(atof(rhs_valueelem.value.c_str()));
        } else if ("MIN" == rhs_valueelem.symbol) {
            asn.v = variant::minvalue();
        } else if ("MAX" == rhs_valueelem.symbol) {
            asn.v = variant::maxvalue();
        }

        context.push(std::move(asn));

        return errorcode_t::success;
    });
}

}  // namespace io
}  // namespace hotplace
