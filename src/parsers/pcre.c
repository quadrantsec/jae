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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <pcre.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "jae-defs.h"
#include "util.h"
#include "rules.h"
#include "counters.h"

#include "parsers/pcre.h"

struct _Rules *Rules;


bool Pcre( uint32_t rule_position, uint8_t s_position, char *json )
{

    int rc = 0;
    int ovector[PCRE_OVECCOUNT];

    rc = pcre_exec( Rules[rule_position].re_pcre[s_position], Rules[rule_position].pcre_extra[s_position], json, (int)strlen(json), 0, 0, ovector, PCRE_OVECCOUNT);

    if ( rc > 0 )
        {
            return(true);
        }

    return(false);

}


