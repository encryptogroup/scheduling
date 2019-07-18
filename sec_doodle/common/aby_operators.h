/**
 \file 		aby_operators.h
 \author	oliver.schick92@gmail.com
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
 Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ABY_SEC_DOODLE_ABY_OPERATORS_H_09072017_2030
#define ABY_SEC_DOODLE_ABY_OPERATORS_H_09072017_2030

#include "config.h"


#include <type_traits>
#include <boost/proto/proto.hpp>

#include <abycore/circuit/booleancircuits.h>
#include <abycore/circuit/arithmeticcircuits.h>
#include <abycore/circuit/circuit.h>

constexpr uint64_t max_val_of_bitlen(unsigned bitlen){
    return (1 << bitlen) - 1;
}

struct functional_share{
    share* s;
    uint64_t max_val;
    
    functional_share() = default;
    
    functional_share(share* sh)
    : s(sh), max_val(max_val_of_bitlen(sh->get_bitlength())){}
    
    functional_share(share* sh, uint64_t max_val)
    : s(sh), max_val(max_val & max_val_of_bitlen(sh->get_max_bitlength())){}
    
    operator share*(){
        return s;
    }
    
    share& operator*(){
        return *s;
    }
    
    share const& operator*() const{
        return *s;
    }
    
    share* operator->(){
        return s;
    }
    
    share const* operator->() const{
        return s;
    }
    
    functional_share operator[](uint32_t idx){
        return functional_share(s->get_wire_ids_as_share(idx), 1);
    }
};

template<typename UnsignedInteger>
constexpr bool is_unsigned_int(){
    return 
        std::is_same<UnsignedInteger, uint8_t>::value
        || std::is_same<UnsignedInteger, uint16_t>::value
        || std::is_same<UnsignedInteger, uint32_t>::value
        || std::is_same<UnsignedInteger, uint64_t>::value;
}

template<typename UnsignedInteger>
struct input{
    UnsignedInteger val;
    uint32_t bitlen;
    e_role role;
};

constexpr struct {
    template<typename UnsignedInteger> 
    decltype(auto) operator()(UnsignedInteger val, uint32_t bitlen, e_role role) const{
        return boost::proto::as_expr(input<UnsignedInteger>{val, bitlen, role});
    }
} in;

template<typename UnsignedInteger>
struct shared_input{
    UnsignedInteger val;
    uint32_t bitlen;
};

constexpr struct {
    template<typename UnsignedInteger> 
    decltype(auto) operator()(UnsignedInteger val, uint32_t bitlen) const{
        return boost::proto::as_expr(shared_input<UnsignedInteger>{val, bitlen});
    }
} shared_in;

template<typename UnsignedInteger>
struct cons_input{
    UnsignedInteger val;
    uint32_t bitlen;
};

constexpr struct {
    template<typename UnsignedInteger>
    decltype(auto) operator()(UnsignedInteger val, uint32_t bitlen) const{
        return boost::proto::as_expr(cons_input<UnsignedInteger>{val, bitlen});
    }
} cons_in;

template<typename Circ>
struct circuit_context : boost::proto::callable_context<circuit_context<Circ> const>{
        
    typedef 
        boost::proto::callable_context< circuit_context<Circ> const> 
    base_type;
    circuit_context(Circ* circ)
    : base_type(), circ_(circ){}
        
    typedef functional_share result_type;

    template<typename UnsignedInteger>
    result_type operator()(boost::proto::tag::terminal, input<UnsignedInteger> const& in) const{
        return circ_->PutINGate(in.val, in.bitlen, in.role);
    }
    
    template<typename UnsignedInteger>
    result_type operator()(boost::proto::tag::terminal, shared_input<UnsignedInteger> const& in) const{
        return circ_->PutSharedINGate(in.val, in.bitlen);
    }
    
    template<typename UnsignedInteger>
    result_type operator()(boost::proto::tag::terminal, cons_input<UnsignedInteger> const& in) const{
        return circ_->PutCONSGate(in.val, in.bitlen);
    }
    
    result_type operator()(boost::proto::tag::terminal, functional_share const& s) const{
        return s;
    }
    
    //overload operator+
    template<typename LExpr, typename RExpr>
    result_type operator()(boost::proto::tag::plus, LExpr const& lhs, RExpr const& rhs) const{
        using boost::proto::eval;
        functional_share a(eval(lhs, *this)), b( eval(rhs, *this));
        return functional_share(circ_->PutADDGate(a, b), a.max_val + b.max_val);
    }
    //overload operator-
    template<typename LExpr, typename RExpr>
    result_type operator()(boost::proto::tag::minus, LExpr const& lhs, RExpr const& rhs) const{
        using boost::proto::eval;
        functional_share a(eval(lhs, *this)), b( eval(rhs, *this));
        return functional_share(circ_->PutSUBGate(a, b), a.max_val - b.max_val);
    }
    //overload operator*
    template<typename LExpr, typename RExpr>
    result_type operator()(boost::proto::tag::multiplies, LExpr const& lhs, RExpr const& rhs) const{
        using boost::proto::eval;
        functional_share a(eval(lhs, *this)), b( eval(rhs, *this));
        return functional_share(circ_->PutMULGate(a, b), a.max_val * b.max_val);
    }
    //overload operator>
    template<typename LExpr, typename RExpr>
    result_type operator()(boost::proto::tag::greater, LExpr const& lhs, RExpr const& rhs) const{
        using boost::proto::eval;
        return functional_share(circ_->PutGTGate(eval(lhs, *this), eval(rhs, *this)), 1);
    }
    //overload operator<
    template<typename LExpr, typename RExpr>
    result_type operator()(boost::proto::tag::less, LExpr const& lhs, RExpr const& rhs) const{
        using boost::proto::eval;
        return functional_share(circ_->PutGTGate(eval(rhs, *this), eval(lhs, *this)), 1);
    }
    
    //overload if_else (which is the unoverloadable ternary operator ?:)
    template<typename IfExpr, typename IfTrueExpr, typename ElseExpr>
    result_type operator()(
        boost::proto::tag::if_else_, 
        IfExpr const& if_expr, IfTrueExpr const& if_true_expr, ElseExpr const& else_expr
    ) const{
            
        using boost::proto::eval;
        functional_share a(eval(if_true_expr, *this)),
                     b(eval(else_expr, *this)), 
                     c(eval(if_expr, *this));
        return functional_share(circ_->PutMUXGate(a, b, c), std::max(a.max_val, b.max_val));
    }
    
private:
    
    Circ* circ_;
};

template<typename T>
struct is_share : std::false_type{};

template<>
struct is_share<functional_share> : std::true_type{};

BOOST_PROTO_DEFINE_OPERATORS(is_share, boost::proto::default_domain)

constexpr struct{
    template<typename Expr, typename Circ>
    decltype(auto) operator()(Expr const& expr, Circ* circ) const{
        using boost::proto::eval;
        return eval(expr, circuit_context<Circ>(circ));
    }
} put;


constexpr struct{
    template<typename Expr, typename Circ>
    share* operator()(Expr const& expr, Circ* circ, e_role role) const{
        return circ->PutOUTGate(put(expr, circ), role);
    }
    
    template<typename Circ>
    share* operator()(share* s, Circ* circ, e_role role) const{
        return circ->PutOUTGate(s, role);
    }
    //shortcut to prevent evaluation of lifted_share s
    template<typename Circ>
    share* operator()(functional_share s, Circ* circ, e_role role) const{
        return circ->PutOUTGate(s, role);
    }
} retrieve;

constexpr struct{
    template<typename Expr, typename Circ>
    share* operator()(Expr const& expr, Circ* circ) const{
        return circ->PutSharedOUTGate(put(expr, circ));
    }
    
    template<typename Circ>
    share* operator()(share* s, Circ* circ) const{
        return circ->PutSharedOUTGate(s);
    }
    //shortcut to prevent evaluation of lifted_share s
    template<typename Circ>
    share* operator()(functional_share s, Circ* circ) const{
        return circ->PutSharedOUTGate(s);
    }
} retrieve_shared;


#endif