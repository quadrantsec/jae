/* $Id$ */
/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
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

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "util.h"
#include "rules.h"
#include "counters.h"
#include "debug.h"

#include "parsers/json.h"
#include "parsers/search.h"
#include "parsers/pcre.h"
#include "parsers/normalize.h"

#include "processors/engine.h"
#include "processors/bluedot.h"

struct _Rules *Rules;
struct _Counters *Counters;
struct _Config *Config;
struct _Debug *Debug;


void Engine( struct _JSON_Key_String *JSON_Key_String, uint16_t json_count )
{

    uint32_t rule_position = 0;
    uint16_t a = 0;
    uint16_t match = 0;
    uint8_t s_position = 0;
    bool results = false;

    for ( rule_position = 0; rule_position < Counters->rules; rule_position++ )
        {

            /* Parse data that needs to be parsed _before_ rule check */


            if ( Config->parse_ip == PARSE_IP_PRE )
                {

                    if ( Debug->parse_ip )
                        {
                            JAE_Log(DEBUG, "[%s:%lu] Parse_IP working in 'PRE' mode.", __FUNCTION__, pthread_self());
                        }

                    if (  Rules[rule_position].parse_ip_count > 0 )
                        {
                            json_count = Parse_IP( JSON_Key_String, json_count, rule_position );
                        }
                }


            if ( Rules[rule_position].normalize_count > 0 )
                {
                    json_count = Normalize( JSON_Key_String, json_count, rule_position );
                }

            for ( a = 0; a < json_count; a++ )
                {

                    /* search */

                    for ( s_position = 0; s_position < Rules[rule_position].search_string_count; s_position++ )
                        {

                            if ( !strcmp(JSON_Key_String[a].key, Rules[rule_position].search_key[s_position]) )
                                {
                                    if ( Search( rule_position, s_position, JSON_Key_String[a].json ) == true )
                                        {
                                            match++;
                                        }
                                }

                        }

                    /* pcre */

                    for ( s_position = 0; s_position < Rules[rule_position].pcre_count; s_position++ )
                        {

                            if ( !strcmp(JSON_Key_String[a].key, Rules[rule_position].pcre_key[s_position] ))
                                {

                                    if ( Pcre( rule_position, s_position, JSON_Key_String[a].json ) == true )
                                        {
                                            match++;
                                        }
                                }

                        }

                    /* bluedot - alert only - should we verify pcre/string are successful?  */

                    for ( s_position = 0; s_position < Rules[rule_position].bluedot_count; s_position++ )
                        {

                            if ( Rules[rule_position].bluedot_alert[s_position] == BLUEDOT_ALERT_ALERT )
                                {


                                    if ( !strcmp(JSON_Key_String[a].key, Rules[rule_position].bluedot_key[s_position] ) )
                                        {

					/* DONT LIKE THIS AT ALL - If bluedot is enabled,  add query 
					   data to the JSON_Key_String.  Then _check_ the data here
					   for a match.  THat way,  its always added to JSON reguardles
					   of results */


                                            if ( Bluedot( rule_position, s_position, JSON_Key_String[a].json ) == true )
                                                {
						printf("BLUEDOT MATCH\n");
					     match++;
                                                }
                                        }

                                }
                        }

                }

            printf("search_count = %d + pcre_count = %d,  bluedot_count = %d,  match = %d\n", Rules[rule_position].search_string_count, Rules[rule_position].pcre_count, Rules[rule_position].bluedot_count, match);


            /* Was "Search" / "Pcre" successful? */

            if ( match == Rules[rule_position].search_string_count + Rules[rule_position].pcre_count +
	                  Rules[rule_position].bluedot_count )
                {

                    /* Add alert items to our array */

                    printf("** TRIGGER **\n");

                    Match( JSON_Key_String, json_count, rule_position);

                }
        }

}


void Match( struct _JSON_Key_String *JSON_Key_String, uint16_t json_count, uint32_t rule_position )
{

    bool after = true;
    uint16_t i = 0;

    if ( Config->parse_ip == PARSE_IP_POST )
        {

            if ( Debug->parse_ip )
                {
                    JAE_Log(DEBUG, "[%s:%lu] Parse_IP working in 'POST' mode.", __FUNCTION__, pthread_self());
                }

            if (  Rules[rule_position].parse_ip_count > 0 )
                {
                    json_count = Parse_IP( JSON_Key_String, json_count, rule_position );
                }

        }

    /* xbit "local" or "redis" in the rule? */

    /*
    	for ( i = 0; i < json_count; i++ )
    		{
    		printf("Key: |%s|, JSON: |%s|\n", JSON_Key_String[i].key, JSON_Key_String[i].json);
    		}
    */

    after = After( JSON_Key_String, json_count, rule_position );

    Output( JSON_Key_String, json_count, rule_position );


}
