/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#ifndef __AFL_LOOP
#define __AFL_LOOP(x) (fprintf(stderr, "__AFL_LOOP has not been defined\n") && 0)
#endif

// I have verified that this is used when we compile with afl-clang.
// I have verified that this is not used when we compile with /home/afryer/msc/LibAFL/fuzzers/forkserver_simple/AFLplusplus/afl-clang-fast
