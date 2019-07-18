/**
 \file 		sec_doodle.cpp
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

#include "config.h"

#include <iomanip>
#include <ostream>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <vector>
#include <tuple>
#include <numeric>
#include <algorithm>
#include <type_traits>
#include <thread>
#include <chrono>

#include <abycore/sharing/sharing.h>

#include "sec_doodle.h"
#include "faby.h"

constexpr std::size_t GMW = 0, YAO = 1, GMW_WEIGHTED = 2, YAO_WEIGHTED = 3,
                      GMW_HYBRID = 4, YAO_HYBRID = 5, GMW_WEIGHTED_HYBRID = 6, YAO_WEIGHTED_HYBRID = 7,
                      ARITH_GMW = 8, ARITH_YAO = 9, GMW_ARITH_YAO = 10;
std::vector<std::size_t> num_participants{10, 100, 1000, 10000};
std::vector<std::size_t> num_time_slots{10, 20, 30};
std::vector<std::size_t> selections{
    //ARITH_YAO, YAO_HYBRID, GMW_ARITH_YAO, ARITH_GMW, GMW_HYBRID, YAO, GMW
    YAO, YAO_WEIGHTED, GMW, GMW_WEIGHTED
};
constexpr std::size_t runs = 10;
uint32_t last_rng_state;

struct {
    std::vector<share*> debug_output_gates;
    std::vector<unsigned> debug_outputs;
    std::vector<std::string> debug_messages;

    template<typename Share>
    void add_output(Share s, std::string msg){
        debug_output_gates.emplace_back(faby::output(s).get_share());
        debug_messages.emplace_back(std::move(msg));
    }

    template<typename Share>
    void add_output_line(Share&& s, std::string msg){
        this->add_output(std::forward<Share>(s), std::move(msg += '\n'));
    }

    void eval(){
        debug_outputs.reserve(debug_output_gates.size());
        for(share* s : debug_output_gates){
            debug_outputs.emplace_back(s->template get_clear_value<unsigned>());
        }
    }

} debug_output;

std::ostream& operator<<(std::ostream& os, decltype(debug_output) const& dbg){
    for(unsigned i = 0; i < dbg.debug_outputs.size(); ++i){
        std::string const& str = dbg.debug_messages[i];
        unsigned output = dbg.debug_outputs[i];
        if(str.back() == '\n'){
            os << str.substr(0, str.size()-1) << output << '\n';;
        }
        else{
            os << str << output;
        }
    }
    return os;
}

class dual_ostream : public std::ostream{
    std::ostream* os1_, * os2_;
public:
    dual_ostream(std::ostream& os1)
    :os1_(&os1), os2_(nullptr){}

    dual_ostream(std::ostream& os1, std::ostream& os2)
    :os1_(&os1), os2_(&os2){}

    dual_ostream(std::ostream* os1, std::ostream* os2 = nullptr)
    :os1_(os1), os2_(os2){}

    template<typename T>
    friend dual_ostream& operator<<(dual_ostream& ds, T const& t){
        if(ds.os1_ != nullptr) *(ds.os1_) << t;
        if(ds.os2_ != nullptr) *(ds.os2_) << t;
        return ds;
    }
};

std::ostream& operator<<(std::ostream& os, doodle_table const& dt){
    auto print_table_line = [&]{
        for(std::size_t j = 0; j < dt.num_columns+1; ++j){
            os << std::left << std::setfill('-');
            os << std::setw(6) << '+';
        }
        os << "+\n";
    };

    for(std::size_t i = 0; i < dt.num_rows; ++i){
        print_table_line();
        os << std::internal << std::setfill(' ')
           << '|' << std::setw(5) << dt.weights[i];
        for(std::size_t j = 0; j < dt.num_columns; ++j){
            os << std::internal << std::setfill(' ')
               << '|' << std::setw(5)
               << (dt.entries[i*dt.num_columns+j] == 0 ?
                        "yes"
                        : (dt.entries[i*dt.num_columns+j] == 1 ? "maybe" : "no"));
        }
        os << "|\n";
    }
    print_table_line();
    return os;
}

template<typename Target>
struct arithmetic_to{

    faby::yao_share operator()(faby::yao_share const& ys) const{
        return ys;
    }

    faby::gmw_share operator()(faby::gmw_share const& gs) const{
        return gs;
    }

    Target operator()(faby::arithmetic_share&& as) const{
        return Target(std::forward<faby::arithmetic_share>(as));
    }

    Target operator()(faby::arithmetic_share& as) const{
        return Target(as);
    }

};

constexpr struct{
    template<typename InputFunction, typename Conversion = decltype(InputFunction::get_conversion())>
    share* operator()(
        doodle_table const& in_dt,
        InputFunction const& input_function,
        Conversion conv = InputFunction::get_conversion()
    ) const {

        using namespace boost::adaptors;
        using namespace faby;

        //column sums is a list of std::tuple<share_t, share_t>
        //the type of the list and the type of share_t is yet only
        //known to the compiler
        auto column_sums = in_dt.get_columns() | transformed([&](auto const& column){
            auto t = tree_accumulate(
                column,
                [](auto&& lhs, auto&& rhs){
                    using namespace faby;
                    //faby::print_value(std::get<0>(lhs), "lhs1");
                    //faby::print_value(std::get<1>(lhs), "lhs2");
                    //faby::print_value(std::get<0>(rhs), "rhs1");
                    //faby::print_value(std::get<1>(rhs), "rhs2");
                    //faby::print_value(std::get<0>(lhs) + std::get<0>(rhs), "lhs1 + rhs1");
                    return std::make_tuple(
                        std::get<0>(lhs) + std::get<0>(rhs),
                        std::get<1>(lhs) + std::get<1>(rhs)
                    );
                },
                input_function
            );
            return t;

        });

        auto result = tree_accumulate(
            column_sums,
            [](auto&& t1, auto&& t2){
                using share_t = std::decay_t<decltype(std::get<0>(t1))>;
                share_t min_index_t1, min_value_t1, min_index_t2, min_value_t2;
                std::tie(min_index_t1, min_value_t1) = t1;
                std::tie(min_index_t2, min_value_t2) = t2;
                share_t gt = min_value_t1 > min_value_t2;
                return std::make_tuple(
                    if_else(gt, min_index_t2, min_index_t1),
                    if_else(gt, min_value_t2, min_value_t1)
                );
            },
            [&](auto&& sum, std::size_t idx){
                using share_t = std::decay_t<decltype(conv(std::get<0>(sum)))>;
                using circuit_t = typename share_t::circuit_t;
                //static int count = 0;
                auto s1 = conv(std::get<0>(sum));
                auto s2 = conv(std::get<1>(sum));
                //debug_output.add_output_line(s1, std::string("#nos (") + std::to_string(count) + std::string("): "));
                //debug_output.add_output_line(s2, std::string("#no-maybes (") + std::to_string(count) + std::string("): "));
                //faby::print_value(s1, std::string("#nos (") + std::to_string(count) + std::string("): "));
                //faby::print_value(s2, std::string("#no-maybes (") + std::to_string(count) + std::string("): "));
                auto t = std::make_tuple(
                    cons_input<circuit_t>(idx),
                    concat(s1, s2)
                );
                //++count;
                return t;
            }
        );
        return faby::output(std::get<0>(result), ALL);
    }

} buildColumnSumCircuit;

constexpr struct{
    template<typename NoInputFunction>
    std::vector<share*> operator()(
        doodle_table const& dt,
        uint32_t col,
        NoInputFunction const& no_input_function
    ) const {
        using namespace faby;
        std::vector<share*> res;
        res.reserve(dt.column_size());
        for(doodle_entry const& de : dt.column(col)){
            #ifdef TESTING
            res.emplace_back(output(no_input_function(de), ALL));
            #else
            res.emplace_back(output(no_input_function(de), SERVER));
            #endif
        }
        return res;
    }

} retrieve_nos;

std::tuple<doodle_table, doodle_table, doodle_table> generate_tables(std::size_t rows, std::size_t columns, bool is_arithmetic){
    static struct {
        uint32_t state = (srand(time(NULL)), rand());
        unsigned operator()(){
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            return state;
        }
    } rand;
    last_rng_state = rand.state;
	constexpr std::size_t max_weight = 255;
    doodle_table dt, alice_dt, bob_dt;
    dt.entries.reserve(rows*columns);
    dt.num_rows = rows;
    dt.num_columns = columns;
    dt.weights.reserve(columns);
    dt.max_weight = max_weight;

    alice_dt.entries.reserve(rows*columns);
    alice_dt.num_rows = dt.num_rows;
    alice_dt.num_columns = dt.num_columns;
    alice_dt.weights.reserve(columns);
    alice_dt.max_weight = max_weight;

    bob_dt.entries.reserve(rows*columns);
    bob_dt.num_rows = dt.num_rows;
    bob_dt.num_columns = dt.num_columns;
    bob_dt.weights.reserve(columns);
    bob_dt.max_weight = max_weight;

    for(std::size_t i = 0; i < rows*columns; ++i){
        auto r = rand() % 3;
        if(is_arithmetic){
            uint64_t n = 1;
            n = (n << 32) | 1;
            if(r == 0){
                dt.entries.emplace_back(0);
            }
            else if(r == 1){
                dt.entries.emplace_back(1);
            }
            else{
                dt.entries.emplace_back(n);
            }
            n = rand() & std::numeric_limits<uint32_t>::max();
            n = (n << 32) | (rand() & std::numeric_limits<uint32_t>::max());
            alice_dt.entries.emplace_back(n);
            n = ((dt.entries.back() >> 32) - (alice_dt.entries.back() >> 32)) &
                std::numeric_limits<uint32_t>::max();
            n = (n << 32) | ((dt.entries.back() - alice_dt.entries.back())
                            & std::numeric_limits<uint32_t>::max());
            bob_dt.entries.emplace_back(n);
            /*for(int i = 0; i < dt.entries.size(); ++i){
                uint32_t a1 = dt.entries[i] >> 32, b1 = dt.entries[i] & std::numeric_limits<uint32_t>::max();
                uint32_t a2 = alice_dt.entries[i] >> 32, b1 = alice_dt.entries[i] & std::numeric_limits<uint32_t>::max();
                uint32_t a3 = bob_dt.entries[i] >> 32, b1 = bob_dt.entries[i] & std::numeric_limits<uint32_t>::max();
                if(a1 )
            }*/
        }
        else{
            if(r == 0){
                dt.entries.emplace_back(yes);
            }
            else if(r == 1){
                dt.entries.emplace_back(maybe);
            }
            else{
                dt.entries.emplace_back(no);
            }
            r = rand() % 3;
            if(r == 0){
                alice_dt.entries.emplace_back(yes);
            }
            else if(r == 1){
                alice_dt.entries.emplace_back(maybe);
            }
            else{
                alice_dt.entries.emplace_back(no);
            }
            bob_dt.entries.emplace_back(dt.entries.back() ^ alice_dt.entries.back());
        }
    }
    for(std::size_t i = 0; i < rows; ++i){
        dt.weights.emplace_back((rand() % max_weight) + 1);
        alice_dt.weights.emplace_back((rand() % max_weight) + 1);
        bob_dt.weights.emplace_back(dt.weights.back() ^ alice_dt.weights.back());
    }
    return std::make_tuple(dt, alice_dt, bob_dt);
}

constexpr struct{
template<typename InputFunction, typename NoInputFunction, typename Conversion = decltype(InputFunction::get_conversion())>
    std::tuple<uint32_t, std::vector<bool>> operator() (
        dual_ostream& os,
        BooleanCircuit* circ,
        e_role role,
        doodle_table alice_dt,
        doodle_table bob_dt,
        ABYParty* party,
        Sharing* sharing,
        InputFunction const& input_function,
        NoInputFunction const& no_input_function,
        Conversion const& conv = InputFunction::get_conversion()
    ) const {
        auto col = buildColumnSumCircuit(role == SERVER ? bob_dt : alice_dt, input_function, conv);
        os << "number of AND gates: " << circ->GetNumANDGates() << '\n';
        party->ExecCircuit();
        os << "setup time: "
           << party->GetTiming(P_SETUP) << '\n'
           << "online time: "
           << party->GetTiming(P_ONLINE) << '\n'
           << "setup sent data: " << party->GetSentData(P_SETUP) << '\n'
           << "online sent data: " << party->GetSentData(P_ONLINE) << '\n'
           << "setup received data: " << party->GetReceivedData(P_SETUP) << '\n'
           << "online received data: " << party->GetReceivedData(P_ONLINE) << '\n'
           << "max communication rounds: " << sharing->GetMaxCommunicationRounds() << '\n';
        uint32_t best_column = col->template get_clear_value<uint32_t>();
        //debug_output.eval();
        party->Reset();
        auto nos = retrieve_nos(role == SERVER ? bob_dt : alice_dt, best_column, no_input_function);

        party->ExecCircuit();

        std::vector<bool> no_selections;
        no_selections.reserve(nos.size());
        for(auto const& s : nos){
            no_selections.emplace_back(s->template get_clear_value<bool>());
        }
        return std::make_tuple(best_column, no_selections);
    }

} build_and_execute_circuit;

void convert_table(doodle_table& dt){
    for(auto& e : dt.entries){
        if(e > 1){
            e = 3;
        }
    }
}

void check_correctness(doodle_table& dt, std::size_t sel, std::tuple<uint32_t, std::vector<bool>> results){
    using namespace boost::adaptors;
    uint32_t best_column;
    std::vector<bool> no_selections;
    std::tie(best_column, no_selections) = results;
    convert_table(dt);
    std::vector<std::tuple<unsigned, unsigned>> column_sums;
    for(auto const& col : dt.get_columns()){
        auto res = std::accumulate(
            col.begin(), col.end(),
            std::make_tuple(0u, 0u, 0u),
            [&](std::tuple<unsigned, unsigned, unsigned> acc, doodle_entry e){
                unsigned weight = sel == YAO_WEIGHTED || sel == GMW_WEIGHTED ? dt.weights[std::get<2>(acc)] : 1u;
                return std::make_tuple(
                    std::get<0>(acc) + (e == no ? 1u * weight : 0u),
                    std::get<1>(acc) + (e == maybe ? 1u * weight : 0u),
                    std::get<2>(acc) + 1
                );
            }
        );
        unsigned nos = std::get<0>(res), maybes = std::get<1>(res);
        column_sums.emplace_back(std::make_tuple(nos, maybes));
    }

    const std::tuple<unsigned, unsigned> min_sum = std::accumulate(
        column_sums.begin(), column_sums.end(),
        std::make_tuple(std::numeric_limits<unsigned>::max(), std::numeric_limits<unsigned>::max()),
        [](std::tuple<unsigned, unsigned> acc, std::tuple<unsigned, unsigned> cs){
            unsigned no_acc, no_cs, maybe_acc, maybe_cs;
            std::tie(no_acc, maybe_acc) = acc;
            std::tie(no_cs, maybe_cs) = cs;
            if(no_acc < no_cs){
                return acc;
            }
            else if(no_acc > no_cs){
                return cs;
            }
            else if(no_acc == no_cs && maybe_acc < maybe_cs){
                return acc;
            }
            else if(no_acc == no_cs && maybe_acc > maybe_cs){
                return cs;
            }
            else{
                return acc;
            }
        }
    );

    unsigned no_min_sum, maybe_min_sum, best_column_no, best_column_maybe;
    std::tie(no_min_sum, maybe_min_sum) = min_sum;
    std::tie(best_column_no, best_column_maybe) = column_sums[best_column];
    auto print = [&](){
        std::cout << dt;
        unsigned num_nos, num_maybes, num_yes;
        std::vector<std::tuple<unsigned, unsigned, unsigned>> v;
        for(auto const& col : dt.get_columns()){
            num_nos = num_maybes = num_yes = 0;
            for(auto const& e : col){
                num_nos += e == no ? 1 : 0;
                num_maybes += e == maybe ? 1 : 0;
                num_yes += e == yes ? 1 : 0;
            }
            v.emplace_back(std::make_tuple(num_nos, num_maybes, num_yes));
        }

        std::cout << std::internal << std::setfill(' ') << std::setw(6) << ' ';
        for(auto const& t : v){
            std::cout << std::setw(6) << std::get<0>(t);
        }
        std::cout << "\n      ";
        for(auto const& t : v){
            std::cout << std::setw(6) << std::get<1>(t);
        }
        std::cout << "\n      ";
        for(auto const& t : v){
            std::cout << std::setw(6) << std::get<2>(t);
        }
        std::cout << std::endl;

        std::cout << "no_min_sum: " << no_min_sum << std::endl;
        std::cout << "maybe_min_sum: " << maybe_min_sum << std::endl;
        std::cout << "best_column: " << best_column << std::endl;
        for(auto s : column_sums){
            std::cout << std::get<0>(s) << ", ";
        }
        std::cout << "\n";
    };
    //print();

    if(no_min_sum != best_column_no || maybe_min_sum != best_column_maybe){
        print();
        std::cout << debug_output;
        throw std::runtime_error("error best_column is not minimal");
    }

    unsigned int i = 0;
    for(auto it = dt.column(best_column).begin(); it != dt.column(best_column).end(); ++it, ++i){
        if(no_selections[i] != (*it == no)){
            print();
            std::cout << "persons saying no: ";
            for(auto s : no_selections){
                std::cout << s << ", ";
            }
            std::cout << std::endl;
            throw std::runtime_error("error wrong person saying no");
        }
    }

}

struct gmw_input{
    faby::gmw_share operator()(uint64_t val, unsigned bitlen, uint64_t max_val) const{
        return faby::gmw_shared_input(val, bitlen, max_val);
    }

    faby::gmw_share operator()(uint64_t val, unsigned bitlen) const{
        return (*this)(val, bitlen, faby::max_val_of_bitlen(bitlen));
    }

    static auto get_conversion(){
        return arithmetic_to<faby::gmw_share>{};
    }
};

struct yao_input{
    e_role role;

    yao_input(e_role role)
    :role(role){}

    faby::yao_share operator()(uint64_t val, unsigned bitlen, uint64_t max_val) const{
        return faby::yao_input(val, bitlen, role, max_val) ^ faby::yao_dummy_input(bitlen, max_val);
    }

    faby::yao_share operator()(uint64_t val, unsigned bitlen) const{
        return (*this)(val, bitlen, faby::max_val_of_bitlen(bitlen));
    }

    static auto get_conversion(){
        return arithmetic_to<faby::yao_share>{};
    }
};

struct arith_input{
    faby::arithmetic_share operator()(uint64_t val, unsigned bitlen, uint64_t max_val) const{
        return faby::arithmetic_shared_input(val, bitlen, max_val);
    }

    faby::arithmetic_share operator()(uint64_t val, unsigned bitlen) const{
        return (*this)(val, bitlen, faby::max_val_of_bitlen(bitlen));
    }
};

template<typename InputPolicy>
struct non_weighted : InputPolicy{
    using InputPolicy::InputPolicy;
    static constexpr unsigned l = std::is_same<InputPolicy, arith_input>::value ? 32u : 1u;
    static constexpr unsigned m = std::is_same<InputPolicy, arith_input>::value
                                  ? std::numeric_limits<uint32_t>::max()
                                  : 1u;

    auto operator()(doodle_entry entry) const{
        return std::make_tuple(
            static_cast<InputPolicy const&>(*this)(entry >> l, l, 1u)
            , static_cast<InputPolicy const&>(*this)(entry & m, l, 1u)
        );
    }
};

template<typename InputPolicy>
struct weighted : InputPolicy{
    unsigned int max_weight, len;
    //input_policy_share_t is the result type of the calling InputPolicy(uint64_t, unsigned)
    //i.e. the type of a share
    using input_policy_share_t = decltype(std::declval<InputPolicy>()(uint64_t(), unsigned()));
    std::vector<input_policy_share_t> inputs;

    //Args... are the arguments that are forwarded to the constructor of InputPolicy
    template<typename... Args>
    weighted(doodle_table const& dt, Args&&... args)
    : InputPolicy(std::forward<Args>(args)...),
      max_weight(dt.max_weight),
      len(faby::bitlen_of_max_val(dt.max_weight)){
        inputs.reserve(dt.weights.size());
        for(auto const& w : dt.weights){
            inputs.emplace_back(static_cast<InputPolicy const&>(*this)(w, len, max_weight));
        }
    }

    auto operator()(doodle_entry entry, std::size_t idx) const{
        return std::make_tuple(
            expand(static_cast<InputPolicy const&>(*this)(entry >> 1u, 1u), len) & inputs[idx],
            expand(static_cast<InputPolicy const&>(*this)(entry & 1u, 1u), len) & inputs[idx]
        );
    }
};



template<typename InputPolicy>
struct arith_hybrid : InputPolicy{
    using InputPolicy::InputPolicy;

    //Only invokable if InputPolicy is invokable with Args
    template<typename... Args>
    auto operator()(Args&&... args) const
        -> std::enable_if_t<
                faby::is_invokable<InputPolicy(Args&&...)>::value
                , std::tuple<faby::arithmetic_share, faby::arithmetic_share>
            >
    {
        using namespace faby;
        using namespace std;
        //deduced as tuple<share_t, share_t>
        auto tpl = static_cast<InputPolicy const&>(*this)(forward<Args>(args)...);
        //deduced as tuple<arithmetic_share, arithmetic_share>
        auto res = make_tuple(arithmetic_share(get<0>(tpl)), arithmetic_share(get<1>(tpl)));
        return res;
    }
};

template<typename InputPolicy>
struct get_no : InputPolicy{
    using InputPolicy::InputPolicy;
    static constexpr unsigned l = std::is_same<InputPolicy, arith_input>::value ? 32u : 1u;

    auto operator()(doodle_entry entry) const{
        return static_cast<InputPolicy const&>(*this)(entry >> l, l);
    }
};
/*
int32_t test_arith_sec_doodle_circuit(
    e_role role, char* address, uint16_t port, seclvl seclvl,
    uint32_t nvals, uint32_t bitlen, uint32_t nthreads,
    e_mt_gen_alg mt_alg, e_sharing sharing
) {
    static struct {
        uint32_t state = (srand(time(NULL)), rand());
        unsigned operator()(){
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            return state;
        }
    } rand;

    doodle_table dt(
    std::vector<doodle_entry>{
        yes, no, maybe, no, yes,
        no, maybe, yes, no, yes,
        no, no, maybe, yes, yes,
        maybe, maybe, no, no, yes,
        yes, yes, no, maybe, yes
    }, 5, 5);
    doodle_table alice_dt, bob_dt;
    alice_dt.num_columns = 5;
    alice_dt.num_rows = 5;
    bob_dt.num_columns = 5;
    bob_dt.num_rows = 5;
    for(auto const& e : dt.entries){
        auto r = rand() % 4;
        alice_dt.entries.emplace_back(e ^ r);
        bob_dt.entries.emplace_back(r);
    }
    std::cout << dt << std::endl;

    auto col = buildColumnSumCircuit(role == SERVER ? bob_dt : alice_dt, arith_hybrid<non_weighted<gmw_input>>{});
    party.ExecCircuit();
    uint32_t best_column = col->template get_clear_value<uint32_t>();
    party.Reset();
    auto nos = retrieve_nos(role == SERVER ? bob_dt : alice_dt, best_column, get_no<gmw_input>{});
    party.ExecCircuit();
    std::vector<bool> no_selections;
    no_selections.reserve(nos.size());
    for(auto const& s : nos){
        no_selections.emplace_back(s->template get_clear_value<bool>());
    }
    return 0;

}
*/
int32_t test_sec_doodle_circuit(
    e_role role, char* address, uint16_t port, seclvl seclvl,
    uint32_t nvals, uint32_t bitlen, uint32_t nthreads,
    e_mt_gen_alg mt_alg, e_sharing sharing
) {
    std::ofstream of(role == CLIENT ? "output-client.txt" : "output-server.txt");
    dual_ostream ds(of);
    std::cout << (role == SERVER ? "server" : "client") << " output" << std::endl;
    doodle_table dt, alice_dt, bob_dt;

    ABYParty party(role, address, port, seclvl, 32, nthreads, mt_alg);
    std::vector<Sharing*>& sharings = party.GetSharings();
    Circuit* yao_circ = sharings[S_YAO]->GetCircuitBuildRoutine();
    Circuit* gmw_circ = sharings[S_BOOL]->GetCircuitBuildRoutine();
    Circuit* arith_circ = sharings[S_ARITH]->GetCircuitBuildRoutine();
    auto yao_ctx = faby::create_yao_context(yao_circ);
    auto gmw_ctx = faby::create_gmw_context(gmw_circ);
    auto arith_ctx = faby::create_arithmetic_context(arith_circ);    

    for(std::size_t sel : selections){
        e_sharing sh;
        if(sel == GMW){
            sh = S_BOOL;
            ds << "GMW\n";
        }
        else if(sel == YAO){
            sh = S_YAO;
            ds << "YAO\n";
        }
        else if(sel == GMW_WEIGHTED){
            sh = S_BOOL;
            ds << "GMW weighted\n";
        }
        else if(sel == YAO_WEIGHTED){
            sh = S_YAO;
            ds << "YAO weighted\n";
        }
        else if(sel == GMW_HYBRID){
            sh = S_BOOL;
            ds << "GMW hybrid\n";
        }
        else if(sel == YAO_HYBRID){
            sh = S_YAO;
            ds << "YAO hybrid\n";
        }
        else if(sel == GMW_WEIGHTED_HYBRID){
            sh = S_BOOL;
            ds << "GMW weighted hybrid\n";
        }
        else if(sel == YAO_WEIGHTED_HYBRID){
            sh = S_YAO;
            ds << "YAO weighted hybrid\n";
        }
        else if(sel == ARITH_GMW){
            sh = S_ARITH;
            ds << "ARITH->GMW\n";
        }
        else if(sel == ARITH_YAO){
            sh = S_ARITH;
            ds << "ARITH->YAO\n";
        }
        else if(sel == GMW_ARITH_YAO){
            sh = S_BOOL;
            ds << "GMW->ARITH->YAO\n";
        }
        ds << "----------------------------------------\n";
        for(std::size_t t : num_time_slots){
            for(std::size_t p : num_participants){
                if((sel == YAO_WEIGHTED || sel == GMW_WEIGHTED) && p > num_participants.back()/10){
                    continue;
                }
                
                for(int i = 0; i < runs; ++i){
                    std::tie(dt, alice_dt, bob_dt) = generate_tables(p, t, sh == S_ARITH);
                    try{
                        if(sel == GMW){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif  // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(gmw_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    non_weighted<gmw_input>{},
                                    get_no<gmw_input>{}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == YAO){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(yao_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    non_weighted<yao_input>{role},
                                    get_no<yao_input>{role}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == GMW_WEIGHTED){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(gmw_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    weighted<gmw_input>{role == CLIENT ? alice_dt : bob_dt},
                                    get_no<gmw_input>{}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == YAO_WEIGHTED){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(yao_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    weighted<yao_input>{role == CLIENT ? alice_dt : bob_dt, role},
                                    get_no<yao_input>{role}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == GMW_HYBRID){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(yao_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    arith_hybrid<non_weighted<gmw_input>>{},
                                    get_no<gmw_input>{}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == YAO_HYBRID){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(yao_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    arith_hybrid<non_weighted<yao_input>>{role},
                                    get_no<yao_input>{role}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == GMW_WEIGHTED_HYBRID){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(yao_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    arith_hybrid<weighted<gmw_input>>{role == CLIENT ? alice_dt : bob_dt},
                                    get_no<gmw_input>{}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == YAO_WEIGHTED_HYBRID){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(yao_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    arith_hybrid<weighted<yao_input>>{role == CLIENT ? alice_dt : bob_dt, role},
                                    get_no<yao_input>{role}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == ARITH_GMW){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(yao_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    non_weighted<arith_input>{},
                                    get_no<arith_input>{},
                                    arithmetic_to<faby::gmw_share>{}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == ARITH_YAO){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(yao_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    non_weighted<arith_input>{},
                                    get_no<arith_input>{},
                                    arithmetic_to<faby::yao_share>{}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                        else if(sel == GMW_ARITH_YAO){
                            #ifndef CORRECTNESS
                            check_correctness(
                                dt,
                                sel,
                            #endif // CORRECTNESS
                                build_and_execute_circuit(
                                    ds,
                                    static_cast<BooleanCircuit*>(yao_circ),
                                    role,
                                    alice_dt,
                                    bob_dt,
                                    &party,
                                    sharings[sh],
                                    arith_hybrid<non_weighted<gmw_input>>{},
                                    get_no<gmw_input>{},
                                    arithmetic_to<faby::yao_share>{}
                            #ifndef CORRECTNESS
                                )
                            #endif // CORRECTNESS
                            );
                        }
                    }
                    catch(std::runtime_error const& re){
                        std::cerr << "error: " << re.what() << "\n";
                        std::cerr << "rng state: " << last_rng_state << "\n";
                        of << "error: " << re.what() << "\n";
                        of << "rng state: " << last_rng_state << "\n";
                        return 1;
                    }
                    party.Reset();
                    if(sel == GMW){
                        std::cout << "GMW:";
                    }
                    else if(sel == YAO){
                        std::cout << "YAO:";
                    }
                    else if(sel == GMW_WEIGHTED){
                        std::cout << "GMW weighted:";
                    }
                    else if(sel == YAO_WEIGHTED){
                        std::cout << "YAO weighted:";
                    }
                    else if(sel == GMW_HYBRID){
                        std::cout << "GMW hybrid:";
                    }
                    else if(sel == YAO_WEIGHTED){
                        std::cout << "YAO hybrid:";
                    }
                    else if(sel == GMW_WEIGHTED_HYBRID){
                        std::cout << "GMW weighted hybrid:";
                    }
                    else if(sel == YAO_WEIGHTED_HYBRID){
                        std::cout << "YAO weighted hybrid:";
                    }
                    else if(sel == ARITH_GMW){
                        std::cout << "ARITH->GMW:";
                    }
                    else if(sel == ARITH_YAO){
                        std::cout << "ARITH->YAO:";
                    }
                    std::cout << " measured p=" << p << " t=" << t << " run=" << i+1 << "\n";
                    ds << '\n';
                }
            }
        }
        ds << "----------------------------------------\n";
    }
    return 0;
}


std::tuple<std::size_t, std::vector<bool>> execute_circuit(
    ABYParty& party,
    Circuit* circ,
    e_role role,
    algorithm alg,
    doodle_table const& dt
){
    auto yao_ctx = faby::create_yao_context(circ);
    auto gmw_ctx = faby::create_gmw_context(circ);
    auto arith_ctx = faby::create_arithmetic_context(circ);

    share* col;
    if(alg == algorithm::gmw){
        col = buildColumnSumCircuit(dt, non_weighted<gmw_input>{});
    }
    else if(alg == algorithm::yao){
        col = buildColumnSumCircuit(dt, non_weighted<yao_input>{role});
    }
    else if(alg == algorithm::gmw_weighted){
        col = buildColumnSumCircuit(dt, weighted<gmw_input>{dt});
    }
    else if(alg == algorithm::yao_weighted){
        col = buildColumnSumCircuit(dt, weighted<yao_input>{dt, role});
    }
    party.ExecCircuit();
    uint32_t best_column = col->template get_clear_value<uint32_t>();
    party.Reset();
    std::vector<share*> nos;
    if(alg == algorithm::gmw || alg == algorithm::gmw_weighted){
        nos = retrieve_nos(dt, best_column, get_no<gmw_input>{});
    }
    else if(alg == algorithm::yao || alg == algorithm::yao_weighted){
        nos = retrieve_nos(dt, best_column, get_no<yao_input>{role});
    }
    party.ExecCircuit();

    std::vector<bool> no_selections;
    if(role == SERVER){
        no_selections.reserve(nos.size());
        for(auto const& s : nos){
            no_selections.emplace_back(s->template get_clear_value<bool>());
        }
    }
    return std::make_tuple(best_column, no_selections);
}

