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
#include <pthread.h>
#include <string.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "jae-defs.h"
#include "util.h"
#include "rules.h"
#include "counters.h"

#include "parsers/json.h"
#include "parsers/search.h"
#include "parsers/strstr-asm/strstr-hook.h"

#include "processors/engine.h"

struct _Rules *Rules;
//struct _Counters *Counters;


bool Search( uint32_t rule_position, uint8_t s_position, char *json )
{

    uint8_t k = 0;

    if ( Rules[rule_position].search_type[s_position] == SEARCH_TYPE_CONTAINS )
        {

            for ( k = 0; k < Rules[rule_position].search_count[s_position]; k++ )
                {

                    if ( Rules[rule_position].search_case[s_position] == false )
                        {

                            if ( JAE_stristr( json, Rules[rule_position].search_string[s_position][k], true ) )
                                {

                                    if ( Rules[rule_position].search_not[s_position] == true )
                                        {
                                            return(false);
                                        }
                                    else
                                        {
                                            return(true);
                                        }
                                }

                        }
                    else
                        {

                            if ( JAE_strstr( json, Rules[rule_position].search_string[s_position][k] ) )
                                {

                                    if ( Rules[rule_position].search_not[s_position] == true )
                                        {
                                            return(false);
                                        }
                                    else
                                        {
                                            return(true);
                                        }
                                }
                        }
                }

        }
    else
        {

            /* EXACT match */

            for ( k = 0; k < Rules[rule_position].search_count[s_position]; k++ )
                {

                    if ( Rules[rule_position].search_case[s_position] == false )
                        {

                            if ( !strcasecmp( json, Rules[rule_position].search_string[s_position][k]) )
                                {

                                    if ( Rules[rule_position].search_not[s_position] == true )
                                        {
                                            return(false);
                                        }
                                    else
                                        {
                                            return(true);
                                        }
                                }

                        }
                    else
                        {

                            if ( !strcmp( json, Rules[rule_position].search_string[s_position][k] ) )
                                {

                                    if ( Rules[rule_position].search_not[s_position] == true )
                                        {
                                            return(false);
                                        }
                                    else
                                        {
                                            return(true);
                                        }
                                }
                        }
                }
        }


    if ( Rules[rule_position].search_not[s_position] == true )
        {
            printf("NOT RETURN TRUE\n");
            return(true);
        }

    return(false);
}


