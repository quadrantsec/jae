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

/* util-hash.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdint.h>

/***************************************************************************
 * Djd2_Hash - creates a hash based off a string.  This code is from Dan
 * Bernstein.  See http://www.cse.yorku.ca/~oz/hash.html.
 ***************************************************************************/

uint32_t Djb2_Hash( const char *str )
{

    uint32_t hash = 5381;
    int32_t c;

    while ( (c = *str++ ) )
        hash = ((hash << 5) + hash) + c;

    return(hash);
}

