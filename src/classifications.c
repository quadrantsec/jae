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

/* classifications.c
 *
 * Loads the classifications file into memory for future use.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <json.h>

#include "version.h"

#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "rules.h"
#include "classifications.h"
#include "counters.h"
#include "debug.h"

struct _Counters *Counters;
struct _Debug *Debug;
struct _Counters *Counters;
struct _Config *Config;

struct _Classifications *Classifications = NULL;


void Load_Classifications( void )
{

#define BUFFER_SIZE 512

    FILE *cat_file = NULL;
    char buf[BUFFER_SIZE] = { 0 };

    struct json_object *json_in = NULL;
    struct json_object *string_obj = NULL;

    uint16_t line_count = 0;

    __atomic_store_n (&Counters->classifications, 0, __ATOMIC_SEQ_CST);

    JAE_Log(NORMAL, "Loading classifications [%s].", Config->classifications_file);

    if (( cat_file = fopen(Config->classifications_file, "r" )) == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to load %s.  %s!", __FILE__, __LINE__, Config->classifications_file, strerror(errno) );
        }

    while(fgets(buf, BUFFER_SIZE, cat_file) != NULL)
        {

            line_count++;

            /* Skip comments, blank linkes */

            if (buf[0] == '#' || buf[0] == 10 || buf[0] == ';' || buf[0] == 32)
                {
                    continue;
                }
            else
                {

                    Remove_Return( buf );

                    /* Basic JSON validation */

                    if ( Validate_JSON_Simple ( buf ) == false )
                        {
                            JAE_Log(ERROR, "[%s, line %d] JSON appears to be invalid at line %d in %s.  Can't find { } via Validate_JSON_Simple().",  __FILE__, __LINE__, line_count, Config->classifications_file);
                        }

                    /* Parse JSON */

                    json_in = json_tokener_parse( buf );

                    if ( json_in == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Unable to parse JSON \"%s\"", __FILE__, __LINE__, buf);
                        }


                    /*
                                        json_object_object_get_ex(json_in, "category", &string_obj);
                                        const char *category = json_object_get_string(string_obj);

                                        if ( category == NULL )
                                            {
                                                JAE_Log(ERROR, "[%s, line %d] Error.  No 'category' found at line %d in %s.", __FILE__, __LINE__, line_count, Config->processor_bluedot_categories);
                                            }

                                        json_object_object_get_ex(json_in, "code", &string_obj);
                                        const char *code = json_object_get_string(string_obj);

                                        if ( code == NULL )
                                            {
                                                JAE_Log(ERROR, "[%s, line %d] Error.  No 'code' found at line %d in %s.", __FILE__, __LINE__, line_count, Config->processor_bluedot_categories);
                                            }

                    */
                    json_object_object_get_ex(json_in, "category", &string_obj);
                    const char *category = json_object_get_string(string_obj);

                    if ( category == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Error.  No 'category' found at line %d in %s.", __FILE__, __LINE__, line_count, Config->classifications_file);
                        }

                    json_object_object_get_ex(json_in, "description", &string_obj);
                    const char *description = json_object_get_string(string_obj);

                    if ( description == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Error.  No 'description' found at line %d in %s.", __FILE__, __LINE__, line_count, Config->classifications_file);
                        }

                    json_object_object_get_ex(json_in, "priority", &string_obj);
                    const char *priority = json_object_get_string(string_obj);

                    if ( priority == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Error.  No 'prioity' found at line %d in %s.", __FILE__, __LINE__, line_count, Config->classifications_file);
                        }


                    /* Allocate memory for new classification */

                    Classifications = (_Classifications *) realloc(Classifications, (Counters->classifications+1) * sizeof(_Classifications));

                    if ( Classifications == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Classifications. Abort!", __FILE__, __LINE__);
                        }

                    memset(&Classifications[Counters->classifications], 0, sizeof(struct _Classifications));

                    strlcpy(Classifications[Counters->classifications].category, category, MAX_RULE_CLASSIFICATION);
                    strlcpy(Classifications[Counters->classifications].description, description, MAX_RULE_CLASSIFICATION_DESC);
                    Classifications[Counters->classifications].priority = atoi( priority );

                    __atomic_add_fetch(&Counters->classifications, 1, __ATOMIC_SEQ_CST);


                    json_object_put(json_in);

                }

        }


    JAE_Log(NORMAL, "Loaded %d classifications.", Counters->classifications);

}

/****************************************************************************
 * Classtype_Lookup - Simple routine that looks up the classtype
 * (shortname) and returns the classtype's description
 ****************************************************************************/

int16_t Classtype_Lookup( const char *classtype, char *str, size_t size )
{


    uint16_t i = 0;

    for (i = 0; i < Counters->classifications; i++)
        {

            if (!strcmp(classtype, Classifications[i].category))
                {
                    snprintf(str, size, "%s", Classifications[i].description);
                    return 0;
                }
        }

    snprintf(str, sizeof("UNKNOWN"), "UNKNOWN");
    return -1;

}

