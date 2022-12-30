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


/* RETHINGING THIS

   JSON_Key_String[0].json is lwyaas the "orignal json".  Build a new "jae" nest and apend it to the
   original - don't rebuild form the array!  - matter of fact  just pass JSON_Key_String[0].json as a
   single string!  not the array,  add "jae" content to it */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <json.h>
#include <sys/time.h>
#include <time.h>


#include "jae-defs.h"
#include "jae-defs.h"
#include "jae.h"
#include "jae-config.h"

#include "rules.h"
#include "util-time.h"
#include "util-json.h"

#include "parsers/json.h"

extern struct _Rules *Rules;
extern struct _Config *Config;

void Output_JSON_Builder ( struct _JSON_Key_String *JSON_Key_String, uint16_t json_count, uint32_t rule_position, char *str, size_t size)
{

    struct json_object *jobj_jae;

    char tmp[MAX_JSON_SIZE] = { 0 }; 
    char tmp2[MAX_JSON_SIZE] = { 0 }; 

    uint16_t i = 0;
    uint32_t last_bracket = 0;

    struct timeval timestamp;
    char alert_timestamp[64] = { 0 };

    gettimeofday(&timestamp, 0);       /* Store event alert time */
    CreateIsoTimeString(&timestamp, alert_timestamp, sizeof(alert_timestamp));

    jobj_jae = json_object_new_object();

    json_object *jalert_timestamp = json_object_new_string( alert_timestamp );
    json_object_object_add(jobj_jae, "alert_timestamp", jalert_timestamp);

    json_object *jsensor_name = json_object_new_string( Config->sensor_name );
    json_object_object_add(jobj_jae, "sensor_name", jsensor_name);

    json_object *jcluster_name = json_object_new_string( Config->cluster_name );
    json_object_object_add(jobj_jae, "cluster_name", jcluster_name);

    json_object *jsignature_id = json_object_new_int64( Rules[rule_position].signature_id );
    json_object_object_add(jobj_jae, "signature_id", jsignature_id);

    json_object *jrevision = json_object_new_int( Rules[rule_position].revision );
    json_object_object_add(jobj_jae, "revision", jrevision);

    json_object *jdescription = json_object_new_string( Rules[rule_position].description );
    json_object_object_add(jobj_jae, "description", jdescription);

    json_object *jclassification = json_object_new_string( Rules[rule_position].classification );
    json_object_object_add(jobj_jae, "classification", jclassification);

    json_object *jclassification_desc = json_object_new_string( Rules[rule_position].classification_desc );
    json_object_object_add(jobj_jae, "classification_desc", jclassification_desc);

    json_object *jsignature = json_object_new_string( Rules[rule_position].b64_signature_triggered );
    json_object_object_add(jobj_jae, "signature", jsignature);

    if ( Rules[rule_position].add_key_count > 0 )
        {

            char add_key_key_tmp[MAX_ADD_KEY_SIZE] = { 0 };
            char add_key_value_tmp[MAX_ADD_KEY_VALUE_SIZE] = { 0 };

            for ( i = 0; i < Rules[rule_position].add_key_count; i++ )
                {

                    /* Assign key to our nest */

                    snprintf(add_key_key_tmp, MAX_ADD_KEY_SIZE, "%s", Rules[rule_position].add_key_key[i]);

                    json_object *j = json_object_new_string( Rules[rule_position].add_key_value[i] );
                    json_object_object_add(jobj_jae, add_key_key_tmp, j);

                }

        }

    strlcpy(tmp, JSON_Key_String[0].json, MAX_JSON_SIZE); 
    last_bracket = Last_Bracket_Position( tmp ); 
    tmp[ last_bracket ] = '\0';

    snprintf(tmp2, MAX_JSON_SIZE, ", \"jae\": %s", json_object_to_json_string(jobj_jae));
    strlcat(tmp, tmp2, MAX_JSON_SIZE);

    strlcat(tmp, " }", MAX_JSON_SIZE);

    snprintf( str, size, "%s", tmp );

    json_object_put(jobj_jae);


}
