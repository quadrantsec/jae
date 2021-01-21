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

#ifdef HAVE_LIBLOGNORM


#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <liblognorm.h>
#include <json.h>


#include "jae-defs.h"

#include "jae.h"
#include "jae-config.h"

#include "parsers/json.h"
#include "parsers/normalize.h"

#include "rules.h"


/**************************/
/* Globals for liblognorm */
/**************************/

static ln_ctx ctx;
//struct stat liblognorm_fileinfo;


struct _Config *Config;
struct _Rules *Rules;


void Load_Normalize( void )
{

    struct stat liblognorm_fileinfo;

    if((ctx = ln_initCtx()) == NULL)
        {
            JAE_Log(ERROR, "[%s, line %d] Cannot initialize liblognorm context.", __FILE__, __LINE__);
        }

    JAE_Log(NORMAL, "Loading %s for normalization.", Config->normalize_file);

    /* Remember - On reload,  file access will be by the "jae" user! */

    if (stat(Config->normalize_file, &liblognorm_fileinfo))
        {
            JAE_Log(ERROR, "[%s, line %d] Error accessing '%s'. Abort.", __FILE__, __LINE__, Config->normalize_file);
        }

    ln_loadSamples(ctx, Config->normalize_file);

}


uint16_t Normalize( struct _JSON_Key_String *JSON_Key_String, uint16_t json_count, uint32_t rule_position )
{

    uint8_t i = 0;
    uint16_t a = 0;
    uint16_t b = 0;
    uint16_t count = 0;

    uint16_t new_json_count = 0;
    char tmp[MAX_JSON_SIZE] = { 0 };

    struct _JSON_Key_String *JSON_Key_String_Normalize;
    struct json_object *json = NULL;

    JSON_Key_String_Normalize = malloc(sizeof(_JSON_Key_String) * MAX_JSON_NEST );

    if ( JSON_Key_String == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _JSON_Key_String", __FILE__, __LINE__);
        }


    for ( i = 0; i < Rules[rule_position].normalize_count; i++ )
        {

            for ( a = 0; a < json_count; a++ )
                {

                    if ( !strcmp(JSON_Key_String[a].key, Rules[rule_position].normalize_key[i]) )
                        {

			    (void)ln_normalize(ctx, JSON_Key_String[a].json, strlen(JSON_Key_String[a].json), &json);

                            if ( json == NULL )
                                {
				    free(JSON_Key_String_Normalize);
				    json_object_put(json);
                                    return( json_count );
                                }

                            snprintf(tmp, MAX_JSON_SIZE, "%s", json_object_to_json_string(json) );

                            /* Parse liblognorm JSON and get new count */

                            new_json_count = Parse_JSON( tmp, JSON_Key_String_Normalize);

                            count = json_count;

                            /* Add JSON to the "alert" array */

                            for ( b = 0; b < new_json_count; b++ )
                                {

                                    if ( JSON_Key_String_Normalize[b].json[0] != '{' )
                                        {

                                            strlcpy(JSON_Key_String[count].key, JSON_Key_String_Normalize[b].key, MAX_JSON_KEY);
                                            strlcpy(JSON_Key_String[count].json, JSON_Key_String_Normalize[b].json, MAX_JSON_VALUE);

                                            count++;

                                        }

                                }

                            for ( b = 0; b < new_json_count; b++ )
                                {

                                    if ( JSON_Key_String_Normalize[b].json[0] != '{' )
                                        {

                                            snprintf(JSON_Key_String[count].key, MAX_JSON_KEY, ".normalize%s", JSON_Key_String_Normalize[b].key);
                                            strlcpy(JSON_Key_String[count].json, JSON_Key_String_Normalize[b].json, MAX_JSON_VALUE);

                                            count++;


                                        }

                                }


                            json_count = count;

                        }

                }

        }


    free(JSON_Key_String_Normalize);
    json_object_put(json);

    return(json_count);
}

#endif
