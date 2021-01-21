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

/* TODO:  var_to_value for things like "description", etc!
   IMPORTANT:  "key" field needs to be a variable! For syslog compatibilty!
   "break" when no more "searchs" are found (stop the loop */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pcre.h>


#include "jae-defs.h"
#include "jae.h"
#include "jae-config.h"
#include "batch.h"
#include "util.h"
#include "rules.h"
#include "counters.h"
#include "var.h"
#include "debug.h"
#include "classifications.h"

#include "parsers/json.h"

#include "processors/bluedot.h"

struct _Counters *Counters;
struct _Debug *Debug;
struct _Config *Config;

struct _Rules *Rules = NULL;

void Load_Ruleset( const char *ruleset )
{

    uint16_t i = 0;
    uint16_t a = 0;
    uint16_t k = 0;
    uint8_t  z = 0;

    uint64_t check = 0;

    uint8_t pcre_switch = 0;
    char pcre_rule[MAX_PCRE_SIZE] = { 0 };
    uint16_t pcre_options=0;
    uint8_t pcre_count = 0;
    const char *pcre_error;
    int pcre_erroffset;

    uint16_t search_string_count = 0;
    uint8_t ret = 0;

    char tmpkey[MAX_JSON_KEY] = { 0 };
    uint16_t search_count = 0;

    uint16_t json_count = 0;
    uint16_t line_count = 0;

    char rulebuf[MAX_RULE_SIZE] = { 0 };
    char var_to_value[MAX_VAR_VALUE_SIZE] = { 0 };
    char tmp[MAX_SEARCH_STRING_SIZE] = { 0 };

    char *ptr1 = NULL;
    uint8_t count = 0;
    bool flag = false;

    FILE *rulesfile;

    struct _JSON_Key_String *JSON_Key_String;

    JSON_Key_String = malloc(sizeof(_JSON_Key_String) * MAX_JSON_NEST );

    if ( JSON_Key_String == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _JSON_Key_String", __FILE__, __LINE__);
        }

    if (( rulesfile = fopen(ruleset, "r" )) == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Cannot open rule file (%s - %s)", __FILE__, __LINE__, ruleset, strerror(errno));
        }

    /* Rule set tracking here? */

    JAE_Log(NORMAL, "Loading %s rule file.", ruleset);

    while ( fgets(rulebuf, sizeof(rulebuf), rulesfile) != NULL )
        {

            line_count++; 	/* For error displays */


            if (rulebuf[0] == '#' || rulebuf[0] == 10 || rulebuf[0] == ';' || rulebuf[0] == 32)
                {

                    continue;

                }
            else
                {

                    /* Allocate memory for rules, but not comments */

                    Rules = (_Rules *) realloc(Rules, (Counters->rules+1) * sizeof(_Rules));

                    if ( Rules == NULL )
                        {
                            fclose(rulesfile);
                            JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Rules. Abort!", __FILE__, __LINE__);
                        }

                    memset(&Rules[Counters->rules], 0, sizeof(struct _Rules));

                }

            if ( Debug->rules )
                {
                    JAE_Log(DEBUG, "[%s, line %d] RULES: ---------=[ Line: %d, Rule: %d ]=-----------------------------------------", __FILE__, __LINE__, line_count, Counters->rules);
                }


            Remove_Return(rulebuf);

            json_count = Parse_JSON( rulebuf, JSON_Key_String);

            if ( json_count == 1 )
                {
                    free(JSON_Key_String);
                    fclose(rulesfile);
                    JAE_Log(ERROR, "[%s, line %d] Failed to parse rule in %s at line %d", __FILE__, __LINE__, ruleset, line_count);
                }



            /* Store a copy of the rule for reference when triggering */

            unsigned long b64_len = strlen(rulebuf) * 2;
            uint8_t b64_target[b64_len];

            Base64Encode( (const unsigned char*)rulebuf, strlen(rulebuf), b64_target, &b64_len);

            strlcpy(Rules[Counters->rules].b64_signature_triggered, (const char *)b64_target, sizeof(Rules[Counters->rules].b64_signature_triggered));

            /****************************************************************
             * Non-nested one off items ( .signature_id, .reference, etc
             ****************************************************************/

            for ( i = 0; i < json_count; i++ )
                {

                    if ( Debug->rules )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] RULES: %d Key: %s, Value: %s", __FILE__, __LINE__, i, JSON_Key_String[i].key, JSON_Key_String[i].json);
                        }

                    if ( !strcmp( JSON_Key_String[i].key, ".signature_id" ) )
                        {

                            Rules[Counters->rules].signature_id = atol(JSON_Key_String[i].json);

                            if ( Rules[Counters->rules].signature_id == 0 )
                                {
                                    free(JSON_Key_String);
                                    fclose(rulesfile);
                                    JAE_Log(ERROR, "[%s, line %d] Invalid 'signature_id' in %s at line %d", __FILE__, __LINE__, ruleset, line_count);
                                }

                        }

                    else if ( !strcmp( JSON_Key_String[i].key, ".revision" ) )
                        {

                            Rules[Counters->rules].revision = atol(JSON_Key_String[i].json);

                            if ( Rules[Counters->rules].revision == 0 )
                                {
                                    free(JSON_Key_String);
                                    fclose(rulesfile);
                                    JAE_Log(ERROR, "[%s, line %d] Invalid 'revision' in %s at line %d", __FILE__, __LINE__, ruleset, line_count);
                                }

                        }

                    else if ( !strcmp( JSON_Key_String[i].key, ".description" ) )
                        {
                            strlcpy( Rules[Counters->rules].description, JSON_Key_String[i].json, MAX_RULE_DESCRIPTION);
                        }

                    else if ( !strcmp( JSON_Key_String[i].key, ".classification" ) )
                        {

                            strlcpy( Rules[Counters->rules].classification, JSON_Key_String[i].json, MAX_RULE_CLASSIFICATION);

                            if ( Classtype_Lookup( Rules[Counters->rules].classification, Rules[Counters->rules].classification_desc, MAX_RULE_CLASSIFICATION_DESC ) == -1 )
                                {
                                    free(JSON_Key_String);
                                    fclose(rulesfile);
                                    JAE_Log(ERROR, "[%s, line %d] Error: Could find classification of '%s' in %s at line %d. Abort.", __FILE__, __LINE__, Rules[Counters->rules].classification, ruleset, line_count);
                                }


                        }

                    else if ( !strcmp( JSON_Key_String[i].key, ".reference" ) )
                        {
                            strlcpy( Rules[Counters->rules].reference, JSON_Key_String[i].json, MAX_RULE_REFERENCE);
                        }

                }

            /* Sanity check! */

            if ( Rules[Counters->rules].classification[0] == '\0' )
                {
                    free(JSON_Key_String);
                    fclose(rulesfile);
                    JAE_Log(ERROR, "[%s, line %d] Error: No 'classification' specified in %s at line %d is invalid.  Abort.", __FILE__, __LINE__, ruleset, line_count);
                }

            if ( Rules[Counters->rules].description[0] == '\0' )
                {
                    free(JSON_Key_String);
                    fclose(rulesfile);
                    JAE_Log(ERROR, "[%s, line %d] Error: No 'description' specified in %s at line %d is invalid.  Abort.", __FILE__, __LINE__, ruleset, line_count);
                }


            /****************************************************************
            * Get all 'search'/'exclude' optinos
            ****************************************************************/

//            bool flag = 0;

            char *s_e = "search";
            bool not = false;

            for ( z = 0; z < 2; z++ )
                {

                    if ( z == 1 )
                        {
                            s_e = "exclude";
                            not = true;
                        }

                    for ( i = 0; i < json_count; i++ )
                        {

                            for ( a = 0; a < MAX_RULE_SEARCH; a++ )
                                {

                                    snprintf(tmpkey, MAX_JSON_KEY, ".%s.%d.string", s_e, a);
                                    tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                    if ( !strcmp( JSON_Key_String[i].key, tmpkey ) )
                                        {

                                            Var_To_Value( JSON_Key_String[i].json, var_to_value, sizeof(var_to_value));

                                            /* Not a list */

                                            if ( var_to_value[0] != '[' )
                                                {

                                                    Rules[Counters->rules].search_not[search_string_count] = not;

                                                    strlcpy(tmp, var_to_value, MAX_SEARCH_STRING_SIZE);

                                                    ret = Pipe_To_Value( tmp, Rules[Counters->rules].search_string[search_string_count][0], MAX_SEARCH_STRING_SIZE);

                                                    if ( ret > 0 )
                                                        {
                                                            free(JSON_Key_String);
                                                            fclose(rulesfile);
                                                            JAE_Log(ERROR, "[%s, line %d] Error: Got bad hex value in %s at line %d.  Abort.", __FILE__, __LINE__, ruleset, line_count, Rules[Counters->rules].search_string[search_string_count][0]);
                                                        }


                                                    if ( Debug->rules )
                                                        {
                                                            JAE_Log(DEBUG, "[%s, line %d] RULES: [Single] Rules[%d].search_string[%d][0] == %s", __FILE__, __LINE__, Counters->rules, search_string_count );
                                                        }

                                                    Rules[Counters->rules].search_count[search_string_count] = 1;
                                                    search_count=1;

                                                }
                                            else
                                                {

                                                    /* Is a list */

                                                    char *ptr1 = NULL;
                                                    char *tok1 = NULL;
                                                    search_count = 0;

                                                    var_to_value[0] = ' ';
                                                    var_to_value[ strlen(var_to_value) - 2 ] = '\0';

                                                    Rules[Counters->rules].search_not[search_string_count] = not;

                                                    ptr1 = strtok_r(var_to_value, ",", &tok1);

                                                    while ( ptr1 != NULL )
                                                        {

                                                            Between_Quotes( ptr1, Rules[Counters->rules].search_string[search_string_count][search_count],MAX_SEARCH_STRING_SIZE );

                                                            ret = Pipe_To_Value( Rules[Counters->rules].search_string[search_string_count][search_count], tmp, MAX_SEARCH_STRING_SIZE);

                                                            if ( ret > 0 )
                                                                {
                                                                    free(JSON_Key_String);
                                                                    fclose(rulesfile);
                                                                    JAE_Log(ERROR, "[%s, line %d] Error: Got bad hex value in %s at line %d.  Abort.", __FILE__, __LINE__, ruleset, line_count);
                                                                }

                                                            if ( Debug->rules )
                                                                {
                                                                    JAE_Log(DEBUG,"[%s, line %d] RULES: [List] Rules[%d].search_string[%d][%d] == %s", __FILE__, __LINE__, Counters->rules, search_string_count, search_count, tmp);
                                                                }

                                                            strlcpy( Rules[Counters->rules].search_string[search_string_count][search_count], tmp, MAX_SEARCH_STRING_SIZE);

                                                            search_count++;
                                                            Rules[Counters->rules].search_count[search_string_count] = search_count;

                                                            ptr1 = strtok_r(NULL, ",", &tok1);
                                                        }

                                                }


                                            /*****************************/
                                            /* Search for sub key values */
                                            /*****************************/

                                            for ( k = 0; k < json_count; k++ )
                                                {
                                                    /* Search for key */

                                                    snprintf(tmpkey, MAX_JSON_KEY, ".%s.%d.key", s_e, a);
                                                    tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                                    if ( !strcmp( JSON_Key_String[k].key, tmpkey ) )
                                                        {
                                                            strlcpy(Rules[Counters->rules].search_key[search_string_count], JSON_Key_String[k].json, MAX_JSON_KEY);
                                                        }


                                                    snprintf(tmpkey, MAX_JSON_KEY, ".%s.%d.mask", s_e, a);
                                                    tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                                    if ( !strcmp( JSON_Key_String[k].key, tmpkey ) )
                                                        {
                                                            strlcpy(Rules[Counters->rules].search_mask[search_string_count], JSON_Key_String[k].json, MAX_RULE_SEARCH_MASK);
                                                        }


                                                    /* Is search/exclude case sensitive? */

                                                    snprintf(tmpkey, MAX_JSON_KEY, ".%s.%d.case", s_e, a);
                                                    tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                                    if ( !strcmp( JSON_Key_String[k].key, tmpkey ) )
                                                        {

                                                            if ( !strcmp( JSON_Key_String[k].json, "true" ) )
                                                                {
                                                                    Rules[Counters->rules].search_case[search_string_count] = true;
                                                                }

                                                            if ( strcmp( JSON_Key_String[k].json, "true" ) && strcmp( JSON_Key_String[k].json, "false" ) )
                                                                {
                                                                    free(JSON_Key_String);
                                                                    fclose(rulesfile);
                                                                    JAE_Log(ERROR, "[%s, line %d] Error: Expected a 'search' 'case' of 'true' or 'false'  but got '%s' in %s at line %d.  Abort.", __FILE__, __LINE__, JSON_Key_String[i].json, ruleset, line_count);
                                                                }

                                                        }

                                                    /* Search 'type' ( 'contains' or 'exact' ) */

                                                    snprintf(tmpkey, MAX_JSON_KEY, ".%s.%d.type", s_e, a);
                                                    tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                                    if ( !strcmp( JSON_Key_String[k].key, tmpkey ) )
                                                        {

                                                            if ( !strcmp( JSON_Key_String[k].json, "exact" ) )
                                                                {
                                                                    Rules[Counters->rules].search_type[search_string_count] = SEARCH_TYPE_EXACT;
                                                                }

                                                            if ( !strcmp( JSON_Key_String[k].json, "contains" ) )
                                                                {
                                                                    Rules[Counters->rules].search_type[search_string_count] = SEARCH_TYPE_CONTAINS;
                                                                }

                                                            if ( strcmp( JSON_Key_String[k].json, "exact" ) && strcmp( JSON_Key_String[k].json, "contains" ) )
                                                                {
                                                                    free(JSON_Key_String);
                                                                    fclose(rulesfile);
                                                                    JAE_Log(ERROR, "[%s, line %d] Error: Expected a 'search' 'type' of 'exact' or 'contains' but got '%s' in %s at line %d.  Abort.", __FILE__, __LINE__, JSON_Key_String[k].json, ruleset, line_count);
                                                                }

                                                        }

                                                }

                                            search_string_count++;
                                        }

                                }
                        }
                }

            /* Sanity Check! */

            Rules[Counters->rules].search_string_count = search_string_count;
            search_string_count = 0;	/* Reset for next pass */

            if ( Debug->rules )
                {
                    JAE_Log(DEBUG, "[%s, line %d] RULES: Total search items in this rule: %d", __FILE__, __LINE__, Rules[Counters->rules].search_string_count);
                }


            for ( a = 0; a < Rules[Counters->rules].search_string_count; a++ )
                {

                    if ( Debug->rules)
                        {

                            JAE_Log(DEBUG, "[%s, line %d] RULES: Count of nest search: Rules[%d].search_count[%d] == %d", __FILE__, __LINE__, Counters->rules, a, Rules[Counters->rules].search_count[a]);

                            for ( k = 0; k < Rules[Counters->rules].search_count[a]; k++ )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] RULES: Array Contents: |%d %d.%d|%s|%s", __FILE__, __LINE__, Counters->rules, a, k, Rules[Counters->rules].search_key[a], Rules[Counters->rules].search_string[a][k]);

                                }

                        }

                    /* If we have a mask (%SAGAN%),  then setup the new search strings */

                    if ( Rules[Counters->rules].search_mask[a][0] != '\0' )
                        {

                            if ( Debug->rules )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] RULES: Got mask \"%s\"", __FILE__, __LINE__, Rules[Counters->rules].search_mask[a]);
                                }

                            for (k = 0; k < Rules[Counters->rules].search_string_count; k++ )
                                {
                                    Replace_JAE( Rules[Counters->rules].search_mask[a], Rules[Counters->rules].search_string[a][k], tmp, sizeof(tmp));
                                    strlcpy( Rules[Counters->rules].search_string[a][k], tmp, MAX_SEARCH_STRING_SIZE);

                                    if ( Debug->rules )
                                        {
                                            JAE_Log(DEBUG, "[%s, line %d] RULES: New Rules[%d].search_string[%d][%d] wiht mask \"%s\"", __FILE__, __LINE__, Counters->rules, a, k, Rules[Counters->rules].search_string[a][k]);
                                        }
                                }
                        }

                    /* Sanity check */

                    if ( Rules[Counters->rules].search_key[a][0] == '\0' )
                        {
                            free(JSON_Key_String);
                            fclose(rulesfile);
                            JAE_Log(ERROR, "[%s, line %d] Error: `search` option lacks a 'key' option in %s at line %d. Abort.", __FILE__, __LINE__, ruleset, line_count);
                        }

                }

            /* PCRE */

            for ( i = 0; i < json_count; i++ )
                {

                    for ( a = 0; a < MAX_PCRE; a++ )
                        {

                            snprintf(tmpkey, MAX_JSON_KEY, ".pcre.%d.expression", a);
                            tmpkey[ sizeof(tmpkey) - 1] = '\0';

                            if ( !strcmp( JSON_Key_String[i].key, tmpkey ) )
                                {

                                    for ( k = 0; k < strlen(JSON_Key_String[i].json); k++ )
                                        {

                                            /* Find opening for pcre */

                                            if ( JSON_Key_String[i].json[k] == '/' )
                                                {
                                                    pcre_switch++;
                                                }

                                            if ( pcre_switch == 1 )
                                                {
                                                    snprintf(tmp, 2, "%c", JSON_Key_String[i].json[k+1]);
                                                    strlcat(pcre_rule, tmp, MAX_PCRE_SIZE);
                                                    //printf("Would copy: |%c|\n", JSON_Key_String[i].json[k+1]);
                                                }

                                            if ( pcre_switch == 2)
                                                {

                                                    switch(JSON_Key_String[i].json[k+1])
                                                        {

                                                        case 'i':
                                                            pcre_options |= PCRE_CASELESS;
                                                            break;
                                                        case 's':
                                                            pcre_options |= PCRE_DOTALL;
                                                            break;
                                                        case 'm':
                                                            pcre_options |= PCRE_MULTILINE;
                                                            break;
                                                        case 'x':
                                                            pcre_options |= PCRE_EXTENDED;
                                                            break;
                                                        case 'A':
                                                            pcre_options |= PCRE_ANCHORED;
                                                            break;
                                                        case 'E':
                                                            pcre_options |= PCRE_DOLLAR_ENDONLY;
                                                            break;
                                                        case 'G':
                                                            pcre_options |= PCRE_UNGREEDY;
                                                            break;
                                                        }

                                                }


                                        }

                                    /* Error checking */

                                    if ( pcre_switch < 2 )
                                        {
                                            free(JSON_Key_String);
                                            fclose(rulesfile);
                                            JAE_Log(ERROR, "[%s, line %d] Bad PCRE statement in %s at line %d. Abort", __FILE__, __LINE__, ruleset, line_count);
                                        }

                                    /* Clip last / from pcre string */

                                    pcre_rule[ strlen(pcre_rule) - 1 ] = '\0';

                                    /* Compile/study and store the results */

                                    Rules[Counters->rules].re_pcre[pcre_count] = pcre_compile( pcre_rule, pcre_options, &pcre_error, &pcre_erroffset, NULL );

                                    pcre_rule[0] = '\0';
                                    pcre_switch = 0;

#ifdef PCRE_HAVE_JIT

                                    /* If we haeve PCRE JIT,  use it */

                                    if ( Config->pcre_jit == true )
                                        {
                                            pcre_options |= PCRE_STUDY_JIT_COMPILE;
                                        }
#endif


                                    Rules[Counters->rules].pcre_extra[pcre_count] = pcre_study( Rules[Counters->rules].re_pcre[pcre_count], pcre_options, &pcre_error);


#ifdef PCRE_HAVE_JIT

                                    if ( Config->pcre_jit == true )
                                        {

                                            int rc = 0;
                                            int jit = 0;

                                            rc = pcre_fullinfo(Rules[Counters->rules].re_pcre[pcre_count], Rules[Counters->rules].pcre_extra[pcre_count], PCRE_INFO_JIT, &jit);

                                            if (rc != 0 || jit != 1)
                                                {
                                                    JAE_Log(WARN, "[%s, line %d] PCRE JIT does not support regexp in %s at line %d (pcre: \"%s\"). Continuing without PCRE JIT enabled for this rule.", __FILE__, __LINE__, ruleset, line_count, pcre_rule);
                                                }

                                        }

#endif

                                    if (  Rules[Counters->rules].re_pcre[pcre_count]  == NULL )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] PCRE failure in %s at %d [%d: %s].", __FILE__, __LINE__, ruleset, line_count, pcre_erroffset, pcre_error);

                                        }

                                    for ( k = 0; k < json_count; k++ )
                                        {

                                            /* Search for key */

                                            snprintf(tmpkey, MAX_JSON_KEY, ".pcre.%d.key", a);
                                            tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                            if ( !strcmp( JSON_Key_String[k].key, tmpkey ) )
                                                {
                                                    strlcpy(Rules[Counters->rules].pcre_key[pcre_count], JSON_Key_String[k].json, MAX_JSON_KEY);
                                                }


                                        }

                                    if ( Rules[Counters->rules].pcre_key[pcre_count][0] == '\0' )
                                        {

                                            JAE_Log( ERROR, "[%s, line %d] There's no \".key\" specified for \"pre\" in signature id %" PRIu64 ".", __FILE__, __LINE__, Rules[check].signature_id );

                                        }

                                    pcre_count++;
                                    Rules[Counters->rules].pcre_count=pcre_count;

                                }

                        } /* for ( a = 0; a < MAX_PCRE ... */

                }  /* for ( i = 0; i < json_count; (PCRE) */

            /* "add_key" */

            count = 0;

            for ( i = 0; i < json_count; i++ )
                {


                    if (JAE_strstr(JSON_Key_String[i].key, ".add_key."))
                        {

                            (void)strtok_r(JSON_Key_String[i].key, ".", &ptr1);

                            if ( ptr1 == NULL )
                                {
                                    JAE_Log( ERROR, "[%s, line %d] 'add_key' appears to be invalid at signature id %" PRIu64 ".", __FILE__, __LINE__, Rules[check].signature_id );
                                }

                            strlcpy(Rules[Counters->rules].add_key_key[count], ptr1, MAX_ADD_KEY_SIZE);

                            /* Convert variable */

                            Var_To_Value( JSON_Key_String[i].json, var_to_value, sizeof(var_to_value));
                            strlcpy(Rules[Counters->rules].add_key_value[count], var_to_value, MAX_ADD_KEY_VALUE_SIZE);

                            count++;

                            Rules[Counters->rules].add_key_count = count;

                        }

                }

            /* Parse_IP */

            count = 0;
            flag = false;

            for ( i = 0; i < json_count; i++ )
                {

                    for ( a = 0; a < MAX_PARSE_IP; a++ )
                        {
                            flag = false;

                            snprintf(tmpkey, MAX_JSON_KEY, ".parse_ip.%d.key", a);
                            tmpkey[ sizeof(tmpkey) - 1] = '\0';

                            if ( !strcmp( JSON_Key_String[i].key, tmpkey ) )
                                {
                                    strlcpy(Rules[Counters->rules].parse_ip_key[count], JSON_Key_String[i].json, MAX_PARSE_IP_KEY_SIZE);
                                    flag = true;
                                }


                            if ( flag == true )
                                {

                                    /****************************/
                                    /* Search for sub key vales */
                                    /****************************/

                                    for ( k = 0; k < json_count; k++ )
                                        {

                                            snprintf(tmpkey, MAX_JSON_KEY, ".parse_ip.%d.store", a);
                                            tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                            if ( !strcmp( JSON_Key_String[k].key, tmpkey ) )
                                                {
                                                    strlcpy(Rules[Counters->rules].parse_ip_store[count], JSON_Key_String[k].json, MAX_PARSE_IP_KEY_SIZE);
                                                }

                                            snprintf(tmpkey, MAX_JSON_KEY, ".parse_ip.%d.position", a);
                                            tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                            if ( !strcmp( JSON_Key_String[k].key, tmpkey ) )
                                                {
                                                    Rules[Counters->rules].parse_ip_position[count] = atoi(JSON_Key_String[k].json);
                                                }
                                        }

                                    /* Sanity check here? */

                                    if ( Rules[Counters->rules].parse_ip_position[count] == 0 )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] 'parse_ip' has an invalid 'position' in %s at line %d.", __FILE__, __LINE__, ruleset, line_count);
                                        }

                                    if ( Rules[Counters->rules].parse_ip_store[count][0] == '\0'  )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] 'parse_ip' has an invalid 'storen' option  in %s at line %d.", __FILE__, __LINE__, ruleset, line_count);
                                        }

                                    count++;
                                    Rules[Counters->rules].parse_ip_count = count;

                                }
                        }
                }

            /* normalize */

            count = 0;

            for ( i = 0; i < json_count; i++ )
                {

                    for ( a = 0; a < MAX_NORMALIZE; a++ )
                        {

                            snprintf(tmpkey, MAX_JSON_KEY, ".normalize.%d.key", a);
                            tmpkey[ sizeof(tmpkey) - 1] = '\0';

                            if ( !strcmp( JSON_Key_String[i].key, tmpkey ) )
                                {
                                    strlcpy(Rules[Counters->rules].normalize_key[count], JSON_Key_String[i].json, MAX_PARSE_IP_KEY_SIZE);
                                    count++;

                                }
                        }

                    Rules[Counters->rules].normalize_count = count;
                }

            /* bluedot */

            count = 0;
            flag = false;

            for ( i = 0; i < json_count; i++ )
                {

                    for ( a = 0; a < MAX_PARSE_IP; a++ )
                        {
                            flag = false;

                            snprintf(tmpkey, MAX_JSON_KEY, ".bluedot.%d.key", a);
                            tmpkey[ sizeof(tmpkey) - 1] = '\0';

                            if ( !strcmp( JSON_Key_String[i].key, tmpkey ) )
                                {
                                    strlcpy(Rules[Counters->rules].bluedot_key[count], JSON_Key_String[i].json, MAX_BLUEDOT_KEY_SIZE);
                                    flag = true;
                                }


                            if ( flag == true )
                                {

                                    /****************************/
                                    /* Search for sub key vales */
                                    /****************************/

                                    for ( k = 0; k < json_count; k++ )
                                        {
                                            snprintf(tmpkey, MAX_JSON_KEY, ".bluedot.%d.type", a);
                                            tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                            if ( !strcmp( JSON_Key_String[k].key, tmpkey ) )
                                                {

                                                    if ( !strcmp(JSON_Key_String[k].json, "ip" ) )
                                                        {
                                                            Rules[Counters->rules].bluedot_type[count] = BLUEDOT_TYPE_IP;
                                                        }

                                                    else if ( !strcmp(JSON_Key_String[k].json, "hash" ) )
                                                        {
                                                            Rules[Counters->rules].bluedot_type[count] = BLUEDOT_TYPE_HASH;
                                                        }

                                                }

                                            snprintf(tmpkey, MAX_JSON_KEY, ".bluedot.%d.alert", a);
                                            tmpkey[ sizeof(tmpkey) - 1] = '\0';

                                            if ( !strcmp( JSON_Key_String[k].key, tmpkey ) )
                                                {


                                                    if ( !strcmp(JSON_Key_String[k].json, "true" ) )
                                                        {
                                                            Rules[Counters->rules].bluedot_alert[count] = BLUEDOT_ALERT_ALERT;
                                                            __atomic_add_fetch(&Rules[Counters->rules].bluedot_match_count, 1, __ATOMIC_SEQ_CST);
                                                        }

                                                    else if ( !strcmp(JSON_Key_String[k].json, "report" ) )
                                                        {
                                                            Rules[Counters->rules].bluedot_alert[count] = BLUEDOT_ALERT_REPORT;
                                                        }
                                                }
                                        }

                                    /* Sanity check */

                                    count++;
                                    Rules[Counters->rules].bluedot_count = count;

                                }

                        }

                }



            /* After */

            count = 0;

            for ( i = 0; i < json_count; i++ )
                {


                }


            __atomic_add_fetch(&Counters->rules, 1, __ATOMIC_SEQ_CST);

        } /* while ( fgets(rulebuf .... */


    /* Verify we don't have duplicate signature id's! */

    for (a = 0; a < Counters->rules; a++)
        {

            for ( check = a+1; check < Counters->rules; check++ )
                {

                    if ( Rules[check].signature_id  == Rules[a].signature_id  )
                        {
                            free(JSON_Key_String);
                            fclose(rulesfile);

                            JAE_Log( ERROR, "[%s, line %d] Detected duplicate 'signature_id' %" PRIu64 ".", __FILE__, __LINE__, Rules[check].signature_id );
                        }
                }
        }



    free(JSON_Key_String);
    fclose(rulesfile);

    if ( Debug->rules )
        {
            JAE_Log(DEBUG, "[%s, line %d] RULES: -------=[ Rule load complete! Lines processed: %d, Rules Total: %d ]=-------", __FILE__, __LINE__, line_count, Counters->rules );
        }

}

