/**
 \file 		config.h
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

#ifndef ABY_SEC_DOODLE_CONFIG_H_09072017_0745
#define ABY_SEC_DOODLE_CONFIG_H_09072017_0745
//disable range concept checking as it
//doesn't work properly with c++ lambdas
#define BOOST_RANGE_ENABLE_CONCEPT_ASSERT 0
//#define TESTING
#define CORRECTNESS
#endif
