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

#ifdef HAVE_LIBFASTJSON

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include <json.h>

#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "version.h"
#include "debug.h"

#include "parsers/json.h"

struct _Counters *Counters;
struct _Debug *Debug;

uint16_t Parse_JSON ( const char *input, struct _JSON_Key_String *JSON_Key_String )
{

    struct json_object *json_obj = NULL;

    uint16_t i;
    uint16_t array_count = 1;   /* Start at one! */

    uint16_t json_count = 1;

    struct json_object_iterator it;
    struct json_object_iterator itEnd;

    char new_key[MAX_JSON_KEY] = { 0 };
    char tmp_key[MAX_JSON_KEY] = { 0 };

    const char *key = NULL;
    const char *val_str = NULL;

    struct json_object *val;

    /* The raw syslog is the first "nested" level".  Copy that.  This will be the
       first entry in the array  */

    JSON_Key_String[0].key[0] = '\0';
    memcpy(JSON_Key_String[0].json, input, MAX_JSON_VALUE);

//    __atomic_add_fetch(&counters->json_input_count, 1, __ATOMIC_SEQ_CST);

    /* Search through all key/values looking for embedded JSON */

    for (i = 0; i < json_count; i++ )
        {

            if ( JSON_Key_String[i].json[0] == '{' )
                {

                    json_obj = json_tokener_parse(JSON_Key_String[i].json);

                    if ( json_obj != NULL )
                        {
                            it = json_object_iter_begin(json_obj);
                            itEnd = json_object_iter_end(json_obj);

                            while (!json_object_iter_equal(&it, &itEnd))
                                {

                                    key = json_object_iter_peek_name(&it);
                                    val = json_object_iter_peek_value(&it);
                                    val_str = json_object_get_string(val);

                                    snprintf(JSON_Key_String[json_count].key, sizeof(JSON_Key_String[json_count].key), "%s.%s", JSON_Key_String[i].key, key);
                                    JSON_Key_String[json_count].key[ sizeof(JSON_Key_String[json_count].key) - 1] = '\0';

                                    strlcpy(JSON_Key_String[json_count].json, val_str, MAX_JSON_VALUE );
                                    json_count++;

                                    json_object_iter_next(&it);

                                }
                        }
                }
        }

    json_object_put(json_obj);

    return(json_count);
}

#endif


