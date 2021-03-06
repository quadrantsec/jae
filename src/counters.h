/* $Id$ */
/*
** Copyright (C) 2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2020 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <stdint.h>

typedef struct _Counters _Counters;
struct _Counters
{

    uint32_t	var;

    uint64_t	input_received;

    uint16_t	classifications;
    uint32_t	rules;

    uint32_t	processor_bluedot_skip;

    uint8_t 	processors_bluedot_cat_count;

    uint16_t 	processor_bluedot_ip_queue;
    uint64_t 	processor_bluedot_ip_cache;
    uint64_t	processor_bluedot_memory_slot;

//    uint16_t 	processor_bluedot_hash_queue;
    uint64_t 	processor_bluedot_hash_cache;
//    uint64_t	processor_bluedot_memory_slot;


};
