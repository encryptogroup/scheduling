/**
 \file 		faby.h
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

#ifndef ABY_SEC_DOODLE_FABY_H_27112017_1017
#define ABY_SEC_DOODLE_FABY_H_27112017_1017

#include <abycore/circuit/booleancircuits.h>
#include <abycore/circuit/arithmeticcircuits.h>
#include <abycore/circuit/circuit.h>
#include <abycore/aby/abyparty.h>
#include <cassert>
#include <limits>

namespace faby{
    
    template<typename T>
    struct always_void{
        using type = void;
    };

    template<typename T, typename = void>
    struct is_invokable : std::false_type{};

    template<typename F, typename... Args>
    struct is_invokable<
        F(Args...),
        typename always_void<decltype(std::declval<F>()(std::declval<Args>()...))>::type
    > : std::true_type {};

    constexpr struct{
        template<typename T>
        inline T operator()(T&& t) const{
            return t;
        }
    } identity;


    template<typename RandomIt, typename BinaryOperation, typename LeafTransformation>
    auto tree_accumulate_impl(RandomIt first, RandomIt last, BinaryOperation& op, LeafTransformation& leaftransformation)
    -> decltype(op(leaftransformation(*first), leaftransformation(*first))){
        return (last - first) == 1 ?
            leaftransformation(*first)
            : op(
                tree_accumulate_impl(first, first + (last - first)/2, op, leaftransformation),
                tree_accumulate_impl(first + (last - first)/2, last, op , leaftransformation)
              );
    }

    template<typename RandomIt, typename BinaryOperation, typename LeafTransformation>
    auto tree_accumulate_impl_with_idx(
        RandomIt first, 
        RandomIt last, 
        BinaryOperation& op, 
        LeafTransformation& leaftransformation,
        RandomIt& base
    ) -> decltype(op(leaftransformation(*first, std::size_t()), leaftransformation(*first, std::size_t()))){
        return (last - first) == 1 ?
                    leaftransformation(*first, first - base)
                    : op(
                        tree_accumulate_impl_with_idx(first, first + (last - first)/2, op, leaftransformation, base),
                        tree_accumulate_impl_with_idx(first + (last - first)/2, last, op, leaftransformation, base)
                      );
            
    }

    template<
        typename RandomIt, 
        typename BinaryOperation, 
        typename LeafTransformation = decltype(identity)&,
        std::enable_if_t<
            is_invokable<LeafTransformation(decltype(*std::declval<RandomIt>()))>::value &&
            !is_invokable<LeafTransformation(decltype(*std::declval<RandomIt>()), std::size_t)>::value
        >* = nullptr
    >
    auto tree_accumulate(RandomIt first, RandomIt last, BinaryOperation&& op, LeafTransformation&& leaftransformation = identity){
        return tree_accumulate_impl(first, last, op, leaftransformation);
    }

    template<
        typename RandomIt, 
        typename BinaryOperation, 
        typename LeafTransformation = decltype(identity)&,
        std::enable_if_t<
            is_invokable<LeafTransformation(decltype(*std::declval<RandomIt>()), std::size_t)>::value
        >* = nullptr
    >
    auto tree_accumulate(RandomIt first, RandomIt last, BinaryOperation&& op, LeafTransformation&& leaftransformation = identity){
        return tree_accumulate_impl_with_idx(first, last, op, leaftransformation, first);
    }
            
    template<typename RandomAccessRange, typename BinaryOperation, typename LeafTransformation = decltype(identity)&>
    auto tree_accumulate(RandomAccessRange range, BinaryOperation&& op, LeafTransformation&& leaftransformation = identity){
        return tree_accumulate(
            range.begin(), 
            range.end(), 
            std::forward<BinaryOperation>(op), 
            std::forward<LeafTransformation>(leaftransformation)
        );
    }

    constexpr uint64_t max(uint64_t lhs, uint64_t rhs){
        return lhs > rhs ? lhs : rhs;
    }
    
    constexpr uint64_t min(uint64_t lhs, uint64_t rhs){
        return lhs < rhs ? lhs : rhs;
    }
    
    constexpr int64_t abs(int64_t val){
        return val < 0 ? -val : val;
    }
    
    constexpr uint64_t max_val_of_bitlen(uint32_t bitlen){
        return bitlen >= sizeof(uint64_t) * 8 ? 
                    ~static_cast<uint64_t>(0)
                    : (static_cast<uint64_t>(1) << bitlen) - 1;
    }
    
    constexpr uint64_t set_all_bits(uint64_t val){
        val |= val >> 1;
        val |= val >> 2;
        val |= val >> 4;
        val |= val >> 8;
        val |= val >> 16;
        val |= val >> 32;
	return 0;
    }

    constexpr unsigned int bitlen_of_max_val(uint64_t max_val){
        unsigned int count = 1;
        while((max_val = max_val >> 1) != 0){
            ++count;
        }
        return count;
    }
    
    using ABYCircuit = ::Circuit;
    using ABYBooleanCircuit = ::BooleanCircuit;
    using ABYArithmeticCircuit = ::ArithmeticCircuit;
    
    template<typename>
    struct faby_context;
    
    
    class YaoCircuit{
    public:
        static constexpr bool has_bits = true;
        
        YaoCircuit()
        :circ_(nullptr){}
        YaoCircuit(YaoCircuit const&) = default;
        YaoCircuit(YaoCircuit&&) = default;
        YaoCircuit& operator=(YaoCircuit const&) = default;
        YaoCircuit& operator=(YaoCircuit&&) = default;
        
        YaoCircuit(ABYCircuit* circ)
        :circ_(static_cast<ABYBooleanCircuit*>(circ)){}
        YaoCircuit(ABYBooleanCircuit* circ)
        :circ_(circ){}
        
        YaoCircuit& operator=(ABYCircuit* const circ){
            circ_ = static_cast<ABYBooleanCircuit*>(circ);
            return *this;
        }
        
        ABYBooleanCircuit* operator->(){
            return circ_;
        }
        ABYBooleanCircuit& operator*(){
            return *circ_;
        }
        ABYBooleanCircuit const* operator->() const{
            return circ_;
        }
        ABYBooleanCircuit const& operator*() const{
            return *circ_;
        }
        operator ABYBooleanCircuit*(){
            return circ_;
        }
        operator ABYBooleanCircuit const*() const{
            return circ_;
        }
        
    private:
        ABYBooleanCircuit* circ_;
    };
    struct gmw_circuit{
        static constexpr bool has_bits = true;
        
        gmw_circuit()
        :circ_(nullptr){}
        gmw_circuit(gmw_circuit const&) = default;
        gmw_circuit(gmw_circuit&&) = default;
        gmw_circuit& operator=(gmw_circuit const&) = default;
        gmw_circuit& operator=(gmw_circuit&&) = default;
        
        gmw_circuit(ABYCircuit* circ)
        :circ_(static_cast<ABYBooleanCircuit*>(circ)){}
        gmw_circuit(ABYBooleanCircuit* circ)
        :circ_(circ){}
        
        gmw_circuit& operator=(ABYCircuit* const circ){
            circ_ = static_cast<ABYBooleanCircuit*>(circ);
            return *this;
        }
        
        ABYBooleanCircuit* operator->(){
            return circ_;
        }
        ABYBooleanCircuit& operator*(){
            return *circ_;
        }
        ABYBooleanCircuit const* operator->() const{
            return circ_;
        }
        ABYBooleanCircuit const& operator*() const{
            return *circ_;
        }
        operator ABYBooleanCircuit*(){
            return circ_;
        }
        operator ABYBooleanCircuit const*() const{
            return circ_;
        }
        
    private:
        ABYBooleanCircuit* circ_;
    };
    
    struct arithmetic_circuit{
        static constexpr bool has_bits = false;
        
        arithmetic_circuit()
        :circ_(nullptr){}
        arithmetic_circuit(arithmetic_circuit const&) = default;
        arithmetic_circuit(arithmetic_circuit&&) = default;
        arithmetic_circuit& operator=(arithmetic_circuit const&) = default;
        arithmetic_circuit& operator=(arithmetic_circuit&&) = default;
        
        arithmetic_circuit(ABYCircuit* circ)
        :circ_(static_cast<ABYArithmeticCircuit*>(circ)){}
        arithmetic_circuit(ABYArithmeticCircuit* circ)
        :circ_(circ){}
        
        arithmetic_circuit& operator=(ABYCircuit* const circ){
            circ_ = static_cast<ABYArithmeticCircuit*>(circ);
            return *this;
        }
        
        ABYArithmeticCircuit* operator->(){
            return circ_;
        }
        ABYArithmeticCircuit& operator*(){
            return *circ_;
        }
        ABYArithmeticCircuit const* operator->() const{
            return circ_;
        }
        ABYArithmeticCircuit const& operator*() const{
            return *circ_;
        }
        operator ABYArithmeticCircuit*(){
            return circ_;
        }
        operator ABYArithmeticCircuit const*() const{
            return circ_;
        } 

    private:
        ABYArithmeticCircuit* circ_;
    };
    
    
    template<typename CircuitType>
    struct basic_functional_share{
    private:
        share* s;
        uint64_t max_val;
        static CircuitType circuit;
        
    public:
        using circuit_t = CircuitType;
        basic_functional_share() = default;
        basic_functional_share(basic_functional_share const&) = default;
        basic_functional_share(basic_functional_share&&) = default;
        basic_functional_share& operator=(basic_functional_share const&) = default;
        basic_functional_share& operator=(basic_functional_share&&) = default;
        
        basic_functional_share(share* sh)
        : s(sh), max_val(max_val_of_bitlen(sh->get_bitlength())){}
        
        basic_functional_share(share* sh, uint64_t max_v)
        : s(sh), max_val(max_v){
            if(CircuitType::has_bits){
                s->set_bitlength(std::min(bitlen_of_max_val(max_val), s->get_max_bitlength()));
            }
        }
        
        operator share*(){
            return s;
        }
        
        operator share const*() const{
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
        
        basic_functional_share operator[](uint32_t idx) const{
            return basic_functional_share(s->get_wire_ids_as_share(idx), 1);
        }
        
        uint64_t get_max_val() const {
            return max_val;
        }
        
        share* get_share() {
            return *this;
        }
        
        share const* get_share() const {
            return *this;
        }
        
        static ABYCircuit* get_circuit(){
            return circuit;
        }
        
        friend struct faby_context<CircuitType>;
    };
    
    template<typename CircuitType>
    CircuitType basic_functional_share<CircuitType>::circuit;
    
    template<typename>
    struct functional_share;
    
    template<>
    struct functional_share<arithmetic_circuit> : basic_functional_share<arithmetic_circuit>{
        using base_ = basic_functional_share<arithmetic_circuit>;
        using gmw_ = basic_functional_share<gmw_circuit>;
        using yao_ = basic_functional_share<YaoCircuit>;
        using base_::base_;
        
        explicit functional_share(yao_ rhs)
        : base_(
            base_::get_circuit()->PutY2AGate(
                expand_share(rhs.get_share(), yao_::get_circuit())
                , gmw_::get_circuit()
            )
            , rhs.get_max_val()
        ){}
        
        explicit functional_share(gmw_ rhs)
        : base_(
            base_::get_circuit()->PutB2AGate(expand_share(rhs.get_share(), gmw_::get_circuit())) 
            , rhs.get_max_val()
        ){}
        
    private:
        static share* expand_share(share* s, Circuit* circ){
            unsigned old_bitlen = s->get_bitlength(), max_bitlength = s->get_max_bitlength();
            unsigned zero = 0u;
            share* zero_share = circ->PutCONSGate(zero, 1u);
            s->set_bitlength(max_bitlength);
            for(std::size_t i = old_bitlen; i < max_bitlength; ++i){
                s->set_wire_id(i, zero_share->get_wire_id(0));
            }
            return s;
        }
    };
    
    template<>
    struct functional_share<YaoCircuit> : basic_functional_share<YaoCircuit>{
        using base_ = basic_functional_share<YaoCircuit>;
        using arith_ = basic_functional_share<arithmetic_circuit>;
        using gmw_ = basic_functional_share<gmw_circuit>;
        using base_::base_;
        
        explicit functional_share(arith_ rhs)
        : base_(base_::get_circuit()->PutA2YGate(rhs.get_share()), rhs.get_max_val()){}
        
        explicit functional_share(gmw_ rhs)
        : base_(base_::get_circuit()->PutB2YGate(rhs.get_share()), rhs.get_max_val()){}
    };
    
    template<>
    struct functional_share<gmw_circuit> : basic_functional_share<gmw_circuit>{
        using base_ = basic_functional_share<gmw_circuit>;
        using arith_ = basic_functional_share<arithmetic_circuit>;
        using yao_ = basic_functional_share<YaoCircuit>;
        using base_::base_;
        
        explicit functional_share(arith_ rhs)
        : base_(base_::get_circuit()->PutA2BGate(rhs.get_share(), yao_::get_circuit()), rhs.get_max_val()){}
        
        explicit functional_share(yao_ rhs)
        : base_(base_::get_circuit()->PutY2BGate(rhs.get_share()), rhs.get_max_val()){}
    };
    
    template<typename CircuitType>
    struct input_t{
        functional_share<CircuitType> operator()(uint32_t val, uint32_t bitlen, e_role role, uint64_t max_val) const{
            using fs = functional_share<CircuitType>;
            assert(fs::get_circuit() != nullptr);
            return fs(fs::get_circuit()->PutINGate(val, bitlen, role), max_val);
        }
        
        functional_share<CircuitType> operator()(uint64_t val, uint32_t bitlen, e_role role) const{
            return (*this)(val, bitlen, role, max_val_of_bitlen(bitlen));
        }
    }; 
    
    template<typename CircuitType>
    struct cons_input_t{
        functional_share<CircuitType> operator()(uint64_t val, uint32_t bitlen, uint64_t max_val) const{
            using fs = functional_share<CircuitType>;
            assert(fs::get_circuit() != nullptr);
            return fs(fs::get_circuit()->PutCONSGate(val, bitlen), max_val);
        }
        functional_share<CircuitType> operator()(uint64_t val, uint32_t bitlen) const{
            return (*this)(val, bitlen, max_val_of_bitlen(bitlen));
        }
        functional_share<CircuitType> operator()(uint64_t val) const{
            return (*this)(val, bitlen_of_max_val(val), val);
        }
    };
    
    template<typename CircuitType>
    struct shared_input_t{
        functional_share<CircuitType> operator()(uint64_t val, uint32_t bitlen, uint64_t max_val) const{
            using fs = functional_share<CircuitType>;
            assert(fs::get_circuit() != nullptr);
            return fs(fs::get_circuit()->PutSharedINGate(val, bitlen), max_val);
        }
        functional_share<CircuitType> operator()(uint64_t val, uint32_t bitlen) const{
            return (*this)(val, bitlen, max_val_of_bitlen(bitlen));
        }
        functional_share<CircuitType> operator()(uint64_t val) const{
            return (*this)(val, bitlen_of_max_val(val), val);
        }
    };
    
    template<typename CircuitType>
    struct dummy_input_t{
        functional_share<CircuitType> operator()(uint32_t bitlen, uint64_t max_val) const{
            using fs = functional_share<CircuitType>;
            assert(fs::get_circuit() != nullptr);
            return fs(fs::get_circuit()->PutDummyINGate(bitlen), max_val);
        }
        functional_share<CircuitType> operator()(uint32_t bitlen) const{
            return (*this)(bitlen, max_val_of_bitlen(bitlen));
        }
    };
    
    struct output_t{
        template<typename CircuitType>
        functional_share<CircuitType> operator()(functional_share<CircuitType> s, e_role role = ALL) const{
            using fs = functional_share<CircuitType>;
            assert(fs::get_circuit() != nullptr);
            return fs(fs::get_circuit()->PutOUTGate(s, role), s.get_max_val());
        }
    };
    
    struct shared_output_t{
        template<typename CircuitType>
        functional_share<CircuitType> operator()(functional_share<CircuitType> s) const{
            using fs = functional_share<CircuitType>;
            assert(fs::get_circuit() != nullptr);
            return fs::get_circuit()->PutSharedOUTGate(s);
        }
    };
    
    struct print_value_t{
        template<typename CircuitType>
        functional_share<CircuitType> operator()(functional_share<CircuitType> s, std::string infostring) const{
            using fs = functional_share<CircuitType>;
            assert(fs::get_circuit() != nullptr);
            return fs::get_circuit()->PutPrintValueGate(s, std::move(infostring));
        }
    };
    
    template<typename CircuitType>
    constexpr input_t<CircuitType> input;
    constexpr input_t<YaoCircuit> yao_input;
    constexpr input_t<gmw_circuit> gmw_input;
    constexpr input_t<arithmetic_circuit> arithmetic_input;
    template<typename CircuitType>
    constexpr cons_input_t<CircuitType> cons_input;
    constexpr cons_input_t<YaoCircuit> yao_cons_input;
    constexpr cons_input_t<gmw_circuit> gmw_cons_input;
    constexpr cons_input_t<arithmetic_circuit> arithmetic_cons_input;
    template<typename CircuitType>
    constexpr shared_input_t<CircuitType> shared_input;
    constexpr shared_input_t<YaoCircuit> yao_shared_input;
    constexpr shared_input_t<gmw_circuit> gmw_shared_input;
    constexpr shared_input_t<arithmetic_circuit> arithmetic_shared_input;
    template<typename CircuitType>
    constexpr dummy_input_t<CircuitType> dummy_input;
    constexpr dummy_input_t<YaoCircuit> yao_dummy_input;
    constexpr dummy_input_t<gmw_circuit> gmw_dummy_input;
    constexpr dummy_input_t<arithmetic_circuit> arithmetic_dummy_input;
    constexpr output_t output;
    constexpr shared_output_t shared_output;
    constexpr print_value_t print_value;
    
    
    constexpr uint64_t max_val_of_and(uint64_t max_val1, uint64_t max_val2){
        return min(max_val1, max_val2);
    }
    
    constexpr uint64_t max_val_of_xor(uint64_t max_val1, uint64_t max_val2){
        auto biggest = max(max_val1, max_val2);
        auto smallest = min(max_val1, max_val2);
        return biggest | set_all_bits(smallest & biggest);
    }
    
    constexpr uint64_t max_val_of_or(uint64_t max_val1, uint64_t max_val2){
        auto biggest = max(max_val1, max_val2);
        auto smallest = min(max_val1, max_val2);
        return biggest | set_all_bits(smallest & biggest);
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator&(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        using fs = functional_share<CircuitType>;
        assert(fs::get_circuit() != nullptr);
        return fs(fs::get_circuit()->PutANDGate(lhs, rhs), max_val_of_and(lhs.get_max_val(), rhs.get_max_val()));
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator^(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        using fs = functional_share<CircuitType>;
	//std::cout << "YAO: " << functional_share<YaoCircuit>::get_circuit() << std::endl; 
	//std::cout << "GMW: " << functional_share<gmw_circuit>::get_circuit() << std::endl; 
	//std::cout << "ARITHMETIC: " << functional_share<arithmetic_circuit>::get_circuit() << std::endl;
//std::cout << "CircuitType: " << functional_share<CircuitType>::get_circuit() << std::endl;
//std::cout << "fs: " << fs::get_circuit() << std::endl;
//std::cout << decltype(fs::get_circuit())(nullptr) << std::endl;
//std::cout << std::boolalpha << (fs::get_circuit() != nullptr) << 
//std::endl;

      assert(fs::get_circuit() != nullptr);
        return fs(fs::get_circuit()->PutXORGate(lhs, rhs), max_val_of_xor(lhs.get_max_val(), rhs.get_max_val()));
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator|(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        using fs = functional_share<CircuitType>;
        assert(fs::get_circuit() != nullptr);
        return fs(fs::get_circuit()->PutORGate(lhs, rhs), max_val_of_or(lhs.get_max_val(), rhs.get_max_val()));
    }
    
    constexpr uint64_t max_val_plus(uint64_t lhs_max_val, uint64_t rhs_max_val){
        uint64_t sum = lhs_max_val + rhs_max_val;
        //check for overflow
        if(sum < lhs_max_val || sum < rhs_max_val){
            sum = std::numeric_limits<uint64_t>::max();
        }
        return sum;
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator+(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        using fs = functional_share<CircuitType>;
        assert(fs::get_circuit() != nullptr);
        return fs(fs::get_circuit()->PutADDGate(lhs, rhs), max_val_plus(lhs.get_max_val(), rhs.get_max_val()));
    }
    
    constexpr uint64_t max_val_sub(uint64_t lhs_max_val, uint64_t rhs_max_val){
        return lhs_max_val;
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator-(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        using fs = functional_share<CircuitType>;
        assert(fs::get_circuit() != nullptr);
        return fs(fs::get_circuit()->PutSUBGate(lhs, rhs), max_val_sub(lhs.get_max_val(), rhs.get_max_val()));
    }
    
    constexpr uint64_t max_val_mul(uint64_t lhs_max_val, uint64_t rhs_max_val){
        //check for overflow
        if(bitlen_of_max_val(lhs_max_val) + bitlen_of_max_val(rhs_max_val) > sizeof(uint64_t) * 8){
            return std::numeric_limits<uint64_t>::max();
        }
        else{
            return lhs_max_val * rhs_max_val;
        }
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator*(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        using fs = functional_share<CircuitType>;
        assert(fs::get_circuit() != nullptr);
        return fs(fs::get_circuit()->PutMULGate(lhs, rhs), max_val_mul(lhs.get_max_val(), rhs.get_max_val()));
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator!(functional_share<CircuitType> bit){
        assert(bit->get_bitlength() == 1);
        return bit ^ cons_input<CircuitType>(1u, 1u);
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator>(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        using fs = functional_share<CircuitType>;
        assert(fs::get_circuit() != nullptr);
        return fs(fs::get_circuit()->PutGTGate(lhs, rhs), 1);
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator<(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        return rhs > lhs;
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator>=(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        return !(lhs < rhs);
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> operator<=(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        return !(lhs > rhs);
    }
    
    template<typename CircuitType>
    inline functional_share<CircuitType> if_else(
        functional_share<CircuitType> condition, 
        functional_share<CircuitType> if_true, 
        functional_share<CircuitType> if_false
    ){
        using fs = functional_share<CircuitType>;
        assert(fs::get_circuit() != nullptr);
        return fs(fs::get_circuit()->PutMUXGate(
            if_true, if_false, condition), std::max(if_true.get_max_val(), if_false.get_max_val())
        );
    }
    
    template<typename>
    struct faby_context;
    
    template<typename C>
    faby_context<C> create_faby_context(ABYCircuit*);
    
    template<typename CircuitType>
    struct faby_context{
    private:
        bool owner_ = false;
        faby_context(ABYCircuit* circuit){
            owner_ = true;
            functional_share<CircuitType>::circuit = circuit;
        }
    public:
        faby_context() = default;
        faby_context(faby_context const&) = delete;
        faby_context(faby_context&& rhs)
        : owner_(rhs.owner_){
            rhs.owner_ = false;
        }
        faby_context& operator=(faby_context const&) = delete;
        faby_context& operator=(faby_context&& rhs){
            if(&rhs != this){
                owner_ = rhs.owner_;
                rhs.owner_ = false;
            }
            return *this;
        }
        ~faby_context(){
            if(owner_){
                functional_share<CircuitType>::circuit = nullptr;
            }
        }
        
        friend faby_context create_faby_context<CircuitType>(ABYCircuit*);
    };
    
    using yao_context = faby_context<YaoCircuit>;
    using gmw_context = faby_context<gmw_circuit>;
    using arithmetic_context = faby_context<arithmetic_circuit>;
    
    template<typename C>
    faby_context<C> create_faby_context(ABYCircuit* circuit){
        if(functional_share<C>::get_circuit() != nullptr){
            throw std::logic_error("context already in use (destroy old context before creating a new one");
        }
        else{
            return faby_context<C>(circuit);
        }
    }
    
    inline faby_context<YaoCircuit> create_yao_context(ABYCircuit* circ){
        return create_faby_context<YaoCircuit>(circ);
    }
    inline faby_context<gmw_circuit> create_gmw_context(ABYCircuit* circ){
        return create_faby_context<gmw_circuit>(circ);
    }
    inline faby_context<arithmetic_circuit> create_arithmetic_context(ABYCircuit* circ){
        return create_faby_context<arithmetic_circuit>(circ);
    }
    
    
    
    template<typename CircuitType>
    functional_share<CircuitType> concat(functional_share<CircuitType> lhs, functional_share<CircuitType> rhs){
        using fs = functional_share<CircuitType>;
        std::vector<uint32_t> result_wires(rhs->get_wires());
        std::vector<uint32_t> const& lhs_wires(lhs->get_wires());
        result_wires.reserve(result_wires.size() + lhs_wires.size());
        for(auto const& wire : lhs_wires){
            result_wires.push_back(wire);
        }
        return fs(
            create_new_share(result_wires, fs::get_circuit()), 
            (lhs.get_max_val() << rhs->get_bitlength()) | rhs.get_max_val()
        );
    }
    template<typename CircuitType>
    functional_share<CircuitType> expand(functional_share<CircuitType> to_expand, std::size_t new_size){
        using fs = functional_share<CircuitType>;
        std::vector<uint32_t> result_wires(to_expand->get_wires());
        uint32_t wire = result_wires.back();
        std::size_t old_size = result_wires.size();
        result_wires.reserve(new_size);
        for(int i = 0; i < new_size - old_size; ++i){
            result_wires.emplace_back(wire);
        }
        return fs(
            create_new_share(result_wires, fs::get_circuit()),
            (max_val_of_bitlen(new_size - old_size) << old_size) | to_expand.get_max_val()
        );
    }
    
    using gmw_share = functional_share<gmw_circuit>;
    using yao_share = functional_share<YaoCircuit>;
    using arithmetic_share = functional_share<arithmetic_circuit>;
}

#endif
