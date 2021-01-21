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
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>


#include "jae-defs.h"
#include "jae.h"
#include "jae-config.h"
#include "rules.h"
#include "debug.h"

#include "parsers/json.h"
#include "parsers/ip.h"

struct _Rules *Rules;
struct _Debug *Debug;


uint16_t Parse_IP( struct _JSON_Key_String *JSON_Key_String, uint16_t json_count, uint32_t rule_position )
{

    uint8_t i = 0;
    uint16_t a = 0;

    char ip[MAX_IP_ADDRESS_SIZE] = { 0 };

    char *ptr1 = NULL;
    char *ptr2 = NULL;

    for ( i = 0; i < Rules[rule_position].parse_ip_count; i++ )
        {

            for ( a = 0; a < json_count; a++ )
                {

                    if ( !strcmp(JSON_Key_String[a].key, Rules[rule_position].parse_ip_key[i]) )
                        {

                            Parse_IP_JSON( JSON_Key_String[a].json, Rules[rule_position].parse_ip_position[i], ip, MAX_IP_ADDRESS_SIZE );

                            strlcpy(JSON_Key_String[json_count].key,  Rules[rule_position].parse_ip_store[i], MAX_JSON_KEY );
                            strlcpy(JSON_Key_String[json_count].json, ip, MAX_IP_ADDRESS_SIZE );

                            json_count++;

                        }
                }
        }

    return(json_count);
}

void Parse_IP_JSON(char *json_string, uint8_t parse_ip_position, char *str, size_t size)
{

    struct sockaddr_in sa;
    uint8_t current_position = 0;
    uint32_t i = 0;

    uint8_t num_colons = 0;
    uint8_t num_dots = 0;
    uint8_t num_hashes = 0;

    bool valid = false;

    char *ptr1 = NULL;
    char *ptr2 = NULL;

    char *ip_1 = NULL;
    char *ip_2 = NULL;

    char mod_json[MAX_JSON_SIZE] = { 0 };

    for (i=0; i<strlen(json_string); i++)
        {

            /* Remove any ", (, ), etc. In case the IP is enclosed like this:
               "192.168.1.1" or (192.168.1.1) */

            if ( json_string[i] != '"' && json_string[i] != '(' && json_string[i] != ')' &&
                    json_string[i] != '[' && json_string[i] != ']' && json_string[i] != '<' &&
                    json_string[i] != '>' && json_string[i] != '{' && json_string[i] != '}' &&
                    json_string[i] != ',' && json_string[i] != '/' && json_string[i] != '@' &&
                    json_string[i] != '=' && json_string[i] != '-' && json_string[i] != '!' &&
                    json_string[i] != '|' && json_string[i] != '_' && json_string[i] != '+' &&
                    json_string[i] != '&' && json_string[i] != '%' && json_string[i] != '$' &&
                    json_string[i] != '~' && json_string[i] != '^' && json_string[i] != '#' &&
                    json_string[i] != '\'' )
                {
                    mod_json[i] = json_string[i];
                    mod_json[i+1] = '\0';
                }
            else
                {
                    mod_json[i] = ' ';
                    mod_json[i+1] = '\0';
                }

        }

    if ( Debug->parse_ip )
        {
            JAE_Log(DEBUG, "[%s:%lu] Modified string: %s", __FUNCTION__, pthread_self(), mod_json);
        }

    ptr1 = strtok_r(mod_json, " ", &ptr2);

    while ( ptr1 != NULL )
        {

            num_colons = 0;
            num_dots = 0;
            num_hashes = 0;
            valid = false;

            /* Get number of colons & dots */

            for (i=0; i<strlen(ptr1); i++)
                {

                    switch(ptr1[i])
                        {

                        case(':'):
                            num_colons++;
                            break;

                        case('.'):
                            num_dots++;
                            break;

                        }

                }

            if ( ( num_colons < 2 && num_dots < 3 ) || ( num_dots > 4 ) )
                {

                    if ( Debug->parse_ip )
                        {
                            JAE_Log(DEBUG, "[%s:%lu] '%s' can't be an IPv4 or IPv6.", __FUNCTION__, pthread_self(), ptr1 );
                        }

                    ptr1 = strtok_r(NULL, " ", &ptr2);          /* move to next token */
                    continue;
                }


            /* Stand alone IPv4 address */

            if ( num_dots == 3 && num_colons == 0 )
                {

                    valid = inet_pton(AF_INET, ptr1, &(sa.sin_addr));

                    if ( valid == true )
                        {

                            current_position++;

                            if ( Debug->parse_ip )
                                {
                                    JAE_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv4 address '%s' position %d **", __FUNCTION__, pthread_self(), ptr1, current_position );
                                }

                            if ( parse_ip_position == current_position )
                                {
                                    snprintf(str, size, "%s", ptr1);
                                    return;
                                }

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }

                        }
                }

            /* Stand alone IPv4 with trailing period */

            if ( num_dots == 4 && ptr1[ strlen(ptr1)-1 ] == '.' )
                {

                    /* Erase the period */

                    ptr1[ strlen(ptr1)-1 ] = '\0';

                    valid = inet_pton(AF_INET, ptr1,  &(sa.sin_addr));

                    if ( valid == true )
                        {

                            current_position++;

                            if ( Debug->parse_ip )
                                {
                                    JAE_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv4 address '%s' with trailing period. **", __FUNCTION__, pthread_self(), ptr1 );
                                }


                            if ( parse_ip_position == current_position )
                                {
                                    snprintf(str, size, "%s", ptr1);
                                    return;
                                }

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }

                        }

                }

            /* IPv4 with 192.168.2.1:12345 or inet:192.168.2.1 */

            if ( num_colons == 1 && num_dots == 3)
                {

                    /* test both sides */

                    ip_1 = strtok_r(ptr1, ":", &ip_2);

                    if ( ip_1 != NULL )
                        {
                            valid = inet_pton(AF_INET, ip_1,  &(sa.sin_addr));
                        }

                    if ( valid == true )
                        {

                            current_position++;

                            if ( Debug->parse_ip )
                                {
                                    JAE_Log(DEBUG, "[%s:%lu] ** Identified IPv4:PORT address '%s'  **", __FUNCTION__, pthread_self(), ip_1 );
                                }


                            if ( parse_ip_position == current_position )
                                {
                                    snprintf(str, size, "%s", ip_1);
                                    return;
                                }

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }

                        }

                    if ( ip_2 != NULL )
                        {
                            valid = inet_pton(AF_INET, ip_2,  &(sa.sin_addr));
                        }

                    if ( valid == true )
                        {

                            current_position++;

                            if ( Debug->parse_ip )
                                {
                                    JAE_Log(DEBUG, "[%s:%lu] ** Identified INTERFACE:IPv4 address '%s'  **", __FUNCTION__, pthread_self(), ip_2 );
                                }


                            if ( parse_ip_position == current_position )
                                {
                                    snprintf(str, size, "%s", ip_2);
                                    return;
                                }

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }
                        }
                }

            /* Stand alone IPv6 */

            if ( num_colons > 2 )
                {

                    valid = inet_pton(AF_INET6, ptr1,  &(sa.sin_addr));

                    if ( valid == true )
                        {

                            current_position++;

                            if ( Debug->parse_ip )
                                {
                                    JAE_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv6 address '%s' **", __FUNCTION__, pthread_self(), ptr1 );
                                }

                            if ( parse_ip_position == current_position )
                                {
                                    snprintf(str, size, "%s", ip_2);
                                    return;
                                }

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }
                        }
                }


            /* Stand alone IPv6 with trailing period */

            if ( num_colons > 2 && ptr1[ strlen(ptr1)-1 ] == '.' )
                {

                    /* Erase the period */

                    ptr1[ strlen(ptr1)-1 ] = '\0';

                    valid = inet_pton(AF_INET6, ptr1,  &(sa.sin_addr));

                    if ( valid == true )
                        {

                            current_position++;

                            if ( Debug->parse_ip )
                                {

                                    JAE_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv6 '%s' with trailing period. **", __FUNCTION__, pthread_self(), ptr1 );
                                }

                            if ( parse_ip_position == current_position )
                                {
                                    snprintf(str, size, "%s", ip_2);
                                    return;
                                }

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }
                        }
                }


            if ( num_colons > 2 && ptr1[0] == ':' && ptr1[1] == ':' && ( ptr1[2] == 'f' || ptr1[2] == 'F' ) &&
                    ( ptr1[3] == 'f' || ptr1[3] == 'F' ) && ( ptr1[4] == 'f' || ptr1[4] == 'F' ) &&
                    ( ptr1[5] == 'f' || ptr1[5] == 'F' ) && ptr1[6] == ':' )
                {

                    uint8_t b = strlen(ptr1);
                    char tmp_ip[MAX_IP_ADDRESS_SIZE] = { 0 };

                    for ( i = 7; b > i; i++)
                        {
                            tmp_ip[i-7] = ptr1[i];
                            tmp_ip[i-6] = '\0';
                        }

                    valid = inet_pton(AF_INET, tmp_ip,  &(sa.sin_addr));

                    if ( valid == true )
                        {

                            current_position++;

                            if ( Debug->parse_ip )
                                {

                                    JAE_Log(DEBUG, "[%s:%lu] ** Identified IPv6 with IPv4 mapping '%s' with trailing period. **", __FUNCTION__, pthread_self(), tmp_ip );
                                }

                            if ( parse_ip_position == current_position )
                                {
                                    snprintf(str, size, "%s", ip_2);
                                    return;
                                }

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }
                        }

                }


            ptr1 = strtok_r(NULL, " ", &ptr2);

        }


    snprintf(str, size, "%s", "NOT_FOUND");
    return;

}



