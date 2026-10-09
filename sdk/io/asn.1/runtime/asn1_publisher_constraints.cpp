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
#include <hotplace/sdk/io/asn.1/asn1_advisor.hpp>
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
    add_handler(
        "Constraints", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("Constraints", {"Constraints", "Constraint"})
            // production("Constraints", {"Constraint"})

            auto size = node->sizeof_rhs();

            if (1 == size) {
                auto& top = context.top();
                top.symbol = node->symbol;
            } else {
                auto cons = context.pop();
                context.pop();

                asn1_semantic_node asn;
                asn.symbol = node->symbol;
                asn.cons.u = cons.cons.u;
                cons.release();  // asn own cons

                context.push(std::move(asn));
            }

            return errorcode_t::success;
        });
    add_handler(
        "Constraint", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("Constraint", {"(", "ConstraintSpec", ")"})

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
    add_handler(
        "ConstraintSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("ConstraintSpec", {"SubtypeElementSetSpec"})
            // production("ConstraintSpec", {"ALL EXCEPT", "SubtypeElementSetSpec"})
            // production("ConstraintSpec", {"ALL", "EXCEPT", "SubtypeElementSetSpec"})

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
                } else if (type_category_t::real == type) {
                    cons = new asn1_constraint_all_except_f(rhs[next].cons.f);
                } else if (type_category_t::literal == type) {
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
    add_handler(
        "SubtypeElementSetSpec", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "|", "SubtypeElement"})
            // production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", ",", "SubtypeElement"})
            // production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "UNION", "SubtypeElement"})
            // production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "EXCEPT", "SubtypeElement"})
            // production("SubtypeElementSetSpec", {"SubtypeElementSetSpec", "SubtypeElement"})
            // production("SubtypeElementSetSpec", {"SubtypeElement"})

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
                if (rhs[1].symbol == "UnionOperation") {
                    auto type = rhs[2].cons.u->type();
                    asn1_constraint_t* cons = nullptr;

                    if (type_category_t::integral == type) {
                        cons = new asn1_constraint_union_i(rhs[0].cons.i, rhs[2].cons.i);
                    } else if (type_category_t::real == type) {
                        cons = new asn1_constraint_union_f(rhs[0].cons.f, rhs[2].cons.f);
                    } else if (type_category_t::literal == type) {
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
                    } else if (type_category_t::real == type) {
                        cons = new asn1_constraint_except_f(rhs[0].cons.f, rhs[2].cons.f);
                    } else if (type_category_t::literal == type) {
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
    add_handler(
        "SubtypeElement", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
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
                if (rhs[1].symbol == "IntersectOperation") {
                    auto type = rhs[2].cons.u->type();
                    asn1_constraint_t* cons = nullptr;

                    if (type_category_t::integral == type) {
                        cons = new asn1_constraint_intersection_i(rhs[0].cons.i, rhs[2].cons.i);
                    } else if (type_category_t::real == type) {
                        cons = new asn1_constraint_intersection_f(rhs[0].cons.f, rhs[2].cons.f);
                    } else if (type_category_t::literal == type) {
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
    // UnionOperation
    // IntersectOperation
    add_handler(
        "PrimaryElement", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
            // production("PrimaryElement", {"ValueElement"})
            // production("PrimaryElement", {"ValueElement", "..", "ValueElement"})             // [from, to]
            // production("PrimaryElement", {"ValueElement", "..", "<", "ValueElement"})        // [from, to)
            // production("PrimaryElement", {"ValueElement", "<", "..", "ValueElement"})        // (from, to]
            // production("PrimaryElement", {"ValueElement", "<", "..", "<", "ValueElement"})   // (from, to)
            // production("PrimaryElement", {"SIZE", "Constraint"})
            // production("PrimaryElement", {"FROM", "Constraint"})
            // production("PrimaryElement", {"PATTERN", symqs})
            // production("PrimaryElement", {"(", "ConstraintSpec", ")"})  // parenthesis recursive structure

            auto size = node->sizeof_rhs();
            std::vector<asn1_semantic_node> rhs(size);
            std::unordered_map<std::string, size_t> index;
            for (size_t i = 0; i < size; ++i) {
                size_t idx = size - 1 - i;
                rhs[idx] = context.pop();
                auto& it = rhs[idx];
                index.emplace(it.symbol, idx);
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
                    // .., <.., ..<, <..<
                    auto iter = index.find("..");
                    auto lhs_flag = range_flag_t::closed;
                    auto rhs_flag = range_flag_t::closed;
                    if (index.end() != iter) {
                        auto fromto = iter->second;
                        if ("<" == rhs[fromto - 1].symbol) lhs_flag = range_flag_t::open;
                        if ("<" == rhs[fromto + 1].symbol) rhs_flag = range_flag_t::open;
                    }

                    size_t next = size - 1;
                    auto& rhs_second = rhs[next];

                    asn1_constraint_t* cons = nullptr;
                    if (rhs_first.v.is_int() && rhs_second.v.is_int()) {
                        cons = new asn1_constraint_range_i(rhs_first.v.value<int64>(), rhs_second.v.value<int64>(), lhs_flag, rhs_flag);
                    } else if (rhs_first.v.is_float() && rhs_second.v.is_float()) {
                        cons = new asn1_constraint_range_f(rhs_first.v.value<double>(), rhs_second.v.value<double>(), lhs_flag, rhs_flag);
                    } else if (rhs_first.v.is_string() && rhs_second.v.is_string()) {
                        std::string qs_lhs = rhs_first.v.value<const char*>();
                        std::string qs_rhs = rhs_second.v.value<const char*>();
                        cons = new asn1_constraint_range_s(qs_lhs, qs_rhs, lhs_flag, rhs_flag);
                    } else if (rhs_first.v.is_minvalue()) {
                        if (rhs_second.v.is_int()) {
                            cons = new asn1_constraint_range_i(range_type_t::minvalue, rhs_second.v.value<int64>(), lhs_flag, rhs_flag);
                        } else if (rhs_second.v.is_float()) {
                            cons = new asn1_constraint_range_f(range_type_t::minvalue, rhs_second.v.value<double>(), lhs_flag, rhs_flag);
                        } else if (rhs_second.v.is_maxvalue()) {
                            cons = new asn1_constraint_range_f(range_type_t::minvalue, range_type_t::maxvalue, lhs_flag, rhs_flag);
                        }
                    } else if (rhs_second.v.is_maxvalue()) {
                        if (rhs_first.v.is_int()) {
                            cons = new asn1_constraint_range_i(rhs_first.v.value<int64>(), range_type_t::maxvalue, lhs_flag, rhs_flag);
                        } else if (rhs_first.v.is_float()) {
                            cons = new asn1_constraint_range_f(rhs_first.v.value<double>(), range_type_t::maxvalue, lhs_flag, rhs_flag);
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
                if (type_category_t::literal == rhs_second.cons.u->type()) {
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
                if ("ConstraintSpec" == rhs[1].symbol) {
                    asn.cons = rhs[1].cons;
                    rhs[1].release();
                }
            }

            context.push(std::move(asn));

            return errorcode_t::success;
        });
    // ObjectSetSpec
    // RelationalConstraint
    add_handler(
        "SizeConstraint", +[](parse_treenode* node, asn1_publisher_context& context, asn1_build_resultset& result) -> return_t {
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
}

}  // namespace io
}  // namespace hotplace
