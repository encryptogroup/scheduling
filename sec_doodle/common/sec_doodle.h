/**
 \file 		sec_doodle.h
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

#ifndef ABY_SEC_DOODLE_SEC_DOODLE_H_09072017_0743
#define ABY_SEC_DOODLE_SEC_DOODLE_H_09072017_0743

#include "config.h"

#include <vector>
#include <iosfwd>
#include <type_traits>

#include <boost/range/counting_range.hpp>
#include <boost/range/adaptor/strided.hpp>
#include <boost/range/adaptor/sliced.hpp>
#include <boost/range/adaptor/transformed.hpp>


#include <abycore/circuit/booleancircuits.h>
#include <abycore/circuit/arithmeticcircuits.h>
#include <abycore/circuit/circuit.h>
#include <abycore/aby/abyparty.h>

enum struct algorithm{
    gmw, yao, gmw_weighted, yao_weighted
};

typedef uint64_t doodle_entry;

constexpr doodle_entry yes = 0;
constexpr doodle_entry maybe = 1;
constexpr doodle_entry no = 3;

struct doodle_table{
private:
    template<typename T>
    static decltype(auto) column_(T* dt, std::size_t i) {
        return dt->entries 
            | boost::adaptors::sliced(i, dt->entries.size()) 
            | boost::adaptors::strided(dt->num_columns);
    }
    
    template<typename T>
    static decltype(auto) row_(T* dt, std::size_t i) {
        return dt->entries 
            | boost::adaptors::sliced(
                dt->num_columns * i, 
                dt->num_columns * (i + 1)
            );
    }
    
    template<typename T>
    static decltype(auto) get_columns_(T* dt) {
        using boost::counting_range;
        using boost::adaptors::transformed;
            
        return counting_range(decltype(num_columns)(0), dt->num_columns) 
               | transformed([dt](std::size_t i){
                     return dt->column(i);
                 });
    }
    
    template<typename T>
    static decltype(auto) get_rows_(T* dt) {
        using boost::counting_range;
        using boost::adaptors::transformed;
        struct Lambda{
            T* dt;
            
            decltype(auto) operator()(std::size_t i) const {
                return dt->row(i);
            }
        } lambda{dt};
        return counting_range(decltype(num_rows)(0), dt->num_rows) | transformed(lambda);
    }
    
public:
    std::vector<doodle_entry> entries;
    std::vector<unsigned int> weights;
    std::size_t num_rows, num_columns, max_weight;
    
    doodle_table() = default;
    
    doodle_table(std::vector<doodle_entry> entries, std::size_t num_rows, std::size_t num_columns)
    : entries(std::move(entries)), num_rows(num_rows), num_columns(num_columns){}
    
    doodle_table(
        std::vector<doodle_entry> entries, 
        std::vector<unsigned int> weights,
        std::size_t num_rows, 
        std::size_t num_columns,
        std::size_t max_weight
    ) 
    : entries(std::move(entries)),
      weights(std::move(weights)),
      num_rows(num_rows), 
      num_columns(num_columns),
      max_weight(max_weight){}
    
    
    decltype(auto) column(std::size_t i) {
        return column_(this, i);
    }
    
    decltype(auto) column(std::size_t i) const {
        return column_(this, i);
    }
    
    decltype(auto) get_columns(){
        return get_columns_(this);
    }
    
    decltype(auto) get_columns() const{
        return get_columns_(this);
    }
    
    decltype(auto) row(std::size_t i) {
        return row_(this, i);
    }
    
    decltype(auto) row(std::size_t i) const{
        return row_(this, i);
    }
    
    decltype(auto) get_rows(){
        return get_rows_(this);
    }
    
    decltype(auto) get_rows() const{
        return get_rows_(this);
    }
    
    std::size_t row_size() const{
        return num_columns;
    }
    
    std::size_t column_size() const{
        return num_rows;
    }
    
    decltype(auto) add_row(){
        entries.resize(entries.size() + num_columns);
        return row(num_rows++);
    }
    
    
};

std::ostream& operator<<(std::ostream&, doodle_table const&);

int32_t test_sec_doodle_circuit(
    e_role role, 
    char* address, 
    uint16_t port, 
    seclvl seclvl,
    uint32_t nvals, 
    uint32_t bitlen, 
    uint32_t nthreads, 
    e_mt_gen_alg mt_alg,
    e_sharing sharing
);


std::tuple<std::size_t, std::vector<bool>> execute_circuit(
    ABYParty& party, 
    Circuit* circ, 
    e_role role, 
    algorithm sel, 
    doodle_table const& dt
);

#endif
