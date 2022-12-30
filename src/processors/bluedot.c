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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <json.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "rules.h"
#include "debug.h"
#include "counters.h"
#include "util-time.h"
#include "util-json.h"
#include "util-tcpip.h"

#include "parsers/json.h"

#include "processors/bluedot.h"



extern struct _Rules *Rules;
extern struct _Debug *Debug;
extern struct _Config *Config;
extern struct _Counters *Counters;
extern struct _Bluedot_Skip *Bluedot_Skip;

struct _Bluedot_Cat_List *BluedotCatList = NULL;

struct _Bluedot_IP_Cache *BluedotIPCache = NULL;
struct _Bluedot_Hash_Cache *BluedotHashCache = NULL;


pthread_mutex_t JAE_DNS_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t BluedotWorkMutex=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t JAEBluedotIPWorkMutex=PTHREAD_MUTEX_INITIALIZER;		// IP queue

struct _Bluedot_IP_Queue *BluedotIPQueue = NULL;
struct _Bluedot_Hash_Queue *BluedotHashQueue = NULL;


bool bluedot_cache_clean_lock=false;
bool bluedot_dns_global = 0;
uint64_t     bluedot_last_time = 0;                    /* For cache cleaning */

void Bluedot_Init( void )
{

    bluedot_last_time = GetEpochTime();

    /* IP Queue & Cache */

    if ( Config->processor_bluedot_ip_queue > 0 )
        {

            BluedotIPQueue = malloc(Config->processor_bluedot_ip_queue * sizeof(struct _Bluedot_IP_Queue));

            if ( BluedotIPQueue == NULL )
                {
                    JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Bluedot_IP_Queue. Abort!", __FILE__, __LINE__);
                }

            memset(BluedotIPQueue, 0, Config->processor_bluedot_ip_queue * sizeof(_Bluedot_IP_Queue));

        }

    if ( Config->processor_bluedot_hash_queue > 0 )
        {

            BluedotHashQueue = malloc(Config->processor_bluedot_hash_queue * sizeof(struct _Bluedot_Hash_Queue));

            if ( BluedotHashQueue == NULL )
                {
                    JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Bluedot_Hash_Queue. Abort!", __FILE__, __LINE__);
                }

            memset(BluedotHashQueue, 0, Config->processor_bluedot_hash_queue * sizeof(_Bluedot_Hash_Queue));

        }


}

void Bluedot_Load_Categories ( void )
{

#define BUFFER_SIZE 512

    FILE *bluedot_cat_file = NULL;
    char buf[BUFFER_SIZE] = { 0 };

    struct json_object *json_in = NULL;
    struct json_object *string_obj = NULL;

    uint16_t line_count = 0;

    __atomic_store_n (&Counters->processors_bluedot_cat_count, 0, __ATOMIC_SEQ_CST);

    JAE_Log(NORMAL, "Loading Bluedot categories [%s].", Config->processor_bluedot_categories);

    if (( bluedot_cat_file = fopen(Config->processor_bluedot_categories, "r" )) == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to load %s.  %s!", __FILE__, __LINE__, Config->processor_bluedot_categories, strerror(errno) );
        }

    while(fgets(buf, BUFFER_SIZE, bluedot_cat_file) != NULL)
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
                            JAE_Log(ERROR, "[%s, line %d] JSON appears to be invalid at line %d in %s.  Can't find { } via Validate_JSON_Simple().",  __FILE__, __LINE__, line_count, Config->processor_bluedot_categories);
                        }

                    /* Parse JSON */

                    json_in = json_tokener_parse( buf );

                    if ( json_in == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Unable to parse JSON \"%s\"", __FILE__, __LINE__, buf);
                        }

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

                    json_object_object_get_ex(json_in, "description", &string_obj);
                    const char *description = json_object_get_string(string_obj);

                    if ( description == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Error.  No 'code' found at line %d in %s.", __FILE__, __LINE__, line_count, Config->processor_bluedot_categories);
                        }

                    /* Allocate memory for new Bluedot category */

                    BluedotCatList = (_Bluedot_Cat_List *) realloc(BluedotCatList, (Counters->processors_bluedot_cat_count+1) * sizeof(_Bluedot_Cat_List));

                    if ( BluedotCatList == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for BluedotCatList. Abort!", __FILE__, __LINE__);
                        }

                    memset(&BluedotCatList[Counters->processors_bluedot_cat_count], 0, sizeof(_Bluedot_Cat_List));

                    strlcpy(BluedotCatList[Counters->processors_bluedot_cat_count].category, category, BLUEDOT_CAT_CATEGORY);
                    strlcpy(BluedotCatList[Counters->processors_bluedot_cat_count].description, description, BLUEDOT_CAT_DESCRIPTION);
                    BluedotCatList[Counters->processors_bluedot_cat_count].code = atoi ( code );

                    __atomic_add_fetch(&Counters->processors_bluedot_cat_count, 1, __ATOMIC_SEQ_CST);

                    json_object_put(json_in);

                }

        }


    JAE_Log(NORMAL, "Loaded %d Bluedot categories.", Counters->processors_bluedot_cat_count);
}


uint16_t Bluedot_Add_JSON( struct _JSON_Key_String *JSON_Key_String, struct _Bluedot_Return *Bluedot_Return, uint16_t json_count, uint32_t rule_position, uint16_t json_position, uint8_t s_position )
{

    int sockfd;
    struct sockaddr_in servaddr;

    struct json_object *json_in = NULL;
    struct json_object *string_obj = NULL;

    uint64_t i = 0;
    uint16_t old_json_count = 0;

    char buff[BLUEDOT_JSON_SIZE] = { 0 };

    unsigned char ip_convert[MAX_IP_BIT_SIZE] = { 0 };

    char *jsonptr = NULL;
    char *jsonptr_f = NULL;
    char json_final[BLUEDOT_JSON_SIZE] = { 0 };

    const char *cdate_utime = NULL;
    uint64_t cdate_utime_u64 = 0;

    const char *mdate_utime = NULL;
    uint64_t mdate_utime_u64 = 0;

    const char *code = NULL;
    uint8_t code_u8 = 0;

    uint64_t epoch_time = GetEpochTime();

    /* If we have "NOT_FOUND", we can skip this */

    if ( JSON_Key_String[json_position].json[0] == 'N' )
        {
            return(json_count);
        }

    /* Check DNS TTL,  do lookup if nessesary */

    if ( bluedot_dns_global == 0 && epoch_time - Config->processor_bluedot_dns_last_lookup > Config->processor_bluedot_dns_ttl )
        {

            if ( Debug->bluedot )
                {
                    JAE_Log(DEBUG, "[%s, line %d] Bluedot host TTL of %d seconds reached.  Doing new lookup for '%s'.", __FILE__, __LINE__, Config->processor_bluedot_dns_ttl, Config->processor_bluedot_host);
                }

            char tmp_host[255] = { 0 };

            pthread_mutex_lock(&JAE_DNS_Mutex);
            bluedot_dns_global = true;

            bool results = false;

            results = DNS_Lookup(Config->processor_bluedot_host, tmp_host, sizeof(tmp_host));

            if ( results == false && Config->processor_bluedot_ip[0] != '\0')
                {
                    JAE_Log(WARN, "[%s, line %d] Cannot lookup DNS for '%s'. Using old value of %s.", __FILE__, __LINE__, Config->processor_bluedot_host, Config->processor_bluedot_ip);

                }
            else
                {

                    strlcpy(Config->processor_bluedot_ip, tmp_host, sizeof(Config->processor_bluedot_ip));

                    if ( Debug->bluedot )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] Bluedot host IP is now: %s", __FILE__, __LINE__, Config->processor_bluedot_ip);
                        }

                }

            Config->processor_bluedot_dns_last_lookup = epoch_time;
            bluedot_dns_global = false;
            pthread_mutex_unlock(&JAE_DNS_Mutex);

        } /* end of DNS lookup */


    /****************************************/
    /* BLUEDOT_TYPE_IP - IP Address lookup! */
    /****************************************/

    if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_IP )
        {

            IP_2_Bit(JSON_Key_String[json_position].json, ip_convert);

            /* Don't look up non-routed stuff */

            if ( Is_Not_Routable(ip_convert) || JSON_Key_String[json_position].json[0] == '0' )
                {

                    if ( Debug->bluedot )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, JSON_Key_String[json_position].json);
                        }

                    return(json_count);
                }

            /* Skip anything in skip network array */

            for ( i = 0; i < Counters->processor_bluedot_skip; i++ )
                {

                    if ( Is_In_Range(ip_convert, (unsigned char *)&Bluedot_Skip[i].range, 1) )
                        {

                            if ( Debug->bluedot )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] IP address %s is in Bluedot 'skip_networks'. Skipping lookup.", __FILE__, __LINE__, JSON_Key_String[json_position].json);
                                }

                            return(json_count);
                        }

                }

            /* Check IP cache,  see if we already have the entry */

            old_json_count = json_count;

            json_count = Check_IP_Cache ( JSON_Key_String, Bluedot_Return, json_count, json_position, ip_convert );

            /* If we have a larger json_count, we've pulled from Cache.  We can stop here */

            if ( json_count > old_json_count )
                {
                    return(json_count);
                }


            /* Check IP queue */

            for ( i =0; i < Config->processor_bluedot_ip_queue; i++ )
                {

                    if ( !memcmp(ip_convert, BluedotIPQueue[i].ip, MAX_IP_BIT_SIZE ))
                        {

                            if (Debug->bluedot)
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] %s is already being looked up by another thread.  Waiting for the data to show up in BluedotIPCache.", __FILE__, __LINE__, JSON_Key_String[json_position].json);
                                }


                            old_json_count = json_count;

                            while ( json_count == old_json_count )
                                {

                                    usleep(1000);

                                    json_count = Check_IP_Cache ( JSON_Key_String, Bluedot_Return, json_count, json_position, ip_convert );
                                }

                            if (Debug->bluedot)
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] Done waiting, got %s out of BluedotIPCache with a category \"%s\".", __FILE__, __LINE__, JSON_Key_String[json_position].json, BluedotIPCache[i].category);
                                }


                            return(json_count);
                        }

                }

            /* Make sure there is enough queue space! */

            if ( Counters->processor_bluedot_ip_queue >= Config->processor_bluedot_ip_queue )
                {
                    JAE_Log(NORMAL, "[%s, line %d] Out of IP queue space! Considering increasing queue size!", __FILE__, __LINE__);
                    return(json_count);
                }

            /* Added entry to queue */

            for (i=0; i < Config->processor_bluedot_ip_queue; i++)
                {

                    /* Find an empty slot */

                    if ( BluedotIPQueue[i].ip[0] == 0 )
                        {
                            pthread_mutex_lock(&JAEBluedotIPWorkMutex);

                            memcpy(BluedotIPQueue[i].ip, ip_convert, MAX_IP_BIT_SIZE);
                            Counters->processor_bluedot_ip_queue++;

                            pthread_mutex_unlock(&JAEBluedotIPWorkMutex);

                            break;

                        }
                }

            snprintf(buff, sizeof(buff), "GET /%s%s%s HTTP/1.1\r\nHost: %s\r\n%s:%s:%s\r\nX-BLUEDOT-DEVICEID: %s\r\nConnection: close\r\n\r\n", Config->processor_bluedot_uri, BLUEDOT_IP_LOOKUP_URL, JSON_Key_String[json_position].json, Config->processor_bluedot_host, BLUEDOT_USER_AGENT, Config->cluster_name, Config->sensor_name, Config->processor_bluedot_device_id);

        } /* End of BLUEDOT_TYPE_IP */

    /************************************************/
    /* BLUEDOT_TYPE_HASH - Bluedot Sha/MD5/etc hash */
    /************************************************/

    else if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_HASH )
        {

            for (i=0; i<Counters->processor_bluedot_hash_cache; i++)
                {

                    if (!strcasecmp(JSON_Key_String[json_position].json, BluedotHashCache[i].hash))
                        {

                            if (Debug->bluedot)
                                {
//                                    JAE_Log(DEBUG, "[%s, line %d] Pulled hash '%s' from Bluedot hash cache with category of \"%s\".", __FILE__, __LINE__, JSON_Key_String[json_position].json, BluedotHashCache[i].category);
                                }

                            // ADD TO JSON

//                            return(true);
                        }

                }

            // CHANGE BACK TO HASH!
            // HERE

        } /* End of BLUEDOT_TYPE_HASH */


    /* Do the lookup! */

    if ( Debug->bluedot )
        {
            JAE_Log(DEBUG, "[%s, line %d] -------------------------------------------------------------", __FILE__, __LINE__);
            JAE_Log(DEBUG, "[%s, line %d] Sending to Bluedot API: %s", __FILE__, __LINE__, buff);
            JAE_Log(DEBUG, "[%s, line %d] -------------------------------------------------------------", __FILE__, __LINE__);
        }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
        {
            JAE_Log(WARN, "[%s, %d] Unable to create socket for Bluedot request!", __FILE__, __LINE__);
            return(json_count);
        }


    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(Config->processor_bluedot_ip);
    servaddr.sin_port = htons(80);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
        {
            JAE_Log(WARN, "[%s, line %d] Unabled to connect to server %s!", __FILE__, __LINE__, Config->processor_bluedot_ip);
            // __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(json_count);
        }

    /* Send request */

    write(sockfd, buff, sizeof(buff));

    /* Get response */

    bzero(buff, sizeof(buff));
    read(sockfd, buff, sizeof(buff));

    /* Close the socket! */

    close(sockfd);

    /* Lookup is complete,  remove from queue */

    Bluedot_Clean_Queue ( JSON_Key_String[json_position].json, Rules[rule_position].bluedot_type[s_position] );

    strtok_r( buff, "{", &jsonptr);
    jsonptr_f = strtok_r( NULL, "{", &jsonptr);

    if ( jsonptr_f == NULL )
        {
            JAE_Log(WARN, "[%s, line %d] Unable to find JSON in server response!", __FILE__, __LINE__);
//            __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(json_count);
        }

    /* The strtork_r removes the first bracket so we re-add it */

    snprintf(json_final, sizeof(json_final), "{%s", jsonptr_f);
    json_final[ sizeof(json_final) - 1 ] = '\0';

    if ( Debug->bluedot == true )
        {
            JAE_Log(DEBUG, "[%s, line %d] Bluedot API Return: %s", __FILE__, __LINE__, json_final);
        }

    json_in = json_tokener_parse(json_final);

    if ( json_in == NULL )
        {
            JAE_Log(WARN, "[%s, line %d] Unable to parse Bluedot JSON: %s", __FILE__, __LINE__, json_final);
            // __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(json_count);
        }

    json_object_object_get_ex(json_in, "code", &string_obj);
    code = json_object_get_string(string_obj);

    if ( code == NULL )
        {
            JAE_Log(WARN, "Bluedot return a qipcode category.");
            //__atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(json_count);
        }

    code_u8 = atoi( code );
    Bluedot_Return->code = code_u8;

    /* IP addess specific codes (create time and modify time) */

    /* DEBUG: Why is this seperate from function below */

    if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_IP )
        {

            json_object_object_get_ex(json_in, "ctime_epoch", &string_obj);
            cdate_utime = json_object_get_string(string_obj);

            if ( cdate_utime != NULL )
                {
                    cdate_utime_u64 = atol(cdate_utime);
                    Bluedot_Return->cdate_utime = cdate_utime_u64;
                }
            else
                {
                    JAE_Log(WARN, "Bluedot return a bad ctime_epoch.");
                }

            json_object_object_get_ex(json_in, "mtime_epoch", &string_obj);
            mdate_utime = json_object_get_string(string_obj);

            if ( mdate_utime != NULL )
                {
                    mdate_utime_u64 = atol(mdate_utime);
                    Bluedot_Return->mdate_utime = mdate_utime_u64;
                }
            else
                {
                    JAE_Log(WARN, "Bluedot return a bad mdate_epoch.");
                }

        }


    /* Add entries to cache */

    if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_IP )
        {

            pthread_mutex_lock(&JAEBluedotIPWorkMutex);

            /* Allocate more memory if needed */

            if ( Counters->processor_bluedot_ip_cache >= Counters->processor_bluedot_memory_slot )
                {

                    Counters->processor_bluedot_memory_slot = Counters->processor_bluedot_memory_slot + BLUEDOT_DEFAULT_MEMORY_SLOTS;

                    BluedotIPCache = (_Bluedot_IP_Cache *) realloc(BluedotIPCache, (Counters->processor_bluedot_memory_slot) * sizeof(_Bluedot_IP_Cache));

                    if ( BluedotIPCache == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for BluedotIPCache. Abort!", __FILE__, __LINE__);
                        }

                    if ( Debug->bluedot )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] Increasing BluedotIPCache cache size by %d. Cache size is now %" PRIu64 "", __FILE__, __LINE__, BLUEDOT_DEFAULT_MEMORY_SLOTS, Counters->processor_bluedot_memory_slot + BLUEDOT_DEFAULT_MEMORY_SLOTS);
                        }

                }

            /* MAKE THIS A FUNCTION? */

            memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].ip, ip_convert, MAX_IP_BIT_SIZE);
            memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].ip_human, JSON_Key_String[json_position].json, INET6_ADDRSTRLEN);
            //strlcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].json, json_final, sizeof(BluedotIPCache[Counters->processor_bluedot_ip_cache].json));
            BluedotIPCache[Counters->processor_bluedot_ip_cache].cache_utime = epoch_time;
            BluedotIPCache[Counters->processor_bluedot_ip_cache].cdate_utime = cdate_utime_u64;
            BluedotIPCache[Counters->processor_bluedot_ip_cache].mdate_utime = mdate_utime_u64;

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.mtime_epoch");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%" PRIu64 "", mdate_utime_u64 );

            json_count++;

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.ctime_epoch");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%" PRIu64 "", cdate_utime_u64 );

            json_count++;

            /* Extract from bluedot JSON */

            json_object_object_get_ex(json_in, "api_user", &string_obj);
            const char *api_user = json_object_get_string(string_obj);

            memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].api_user, api_user, BLUEDOT_API_USER);

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.api_user");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", api_user );

            json_count++;

            json_object_object_get_ex(json_in, "code", &string_obj);
            const char *code = json_object_get_string(string_obj);

            BluedotIPCache[Counters->processor_bluedot_ip_cache].code = code_u8;

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.code");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", code );

            json_count++;

            json_object_object_get_ex(json_in, "category", &string_obj);
            const char *category = json_object_get_string(string_obj);

            memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].category, category, BLUEDOT_CATEGORY);

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.category");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", category );

            json_count++;

            json_object_object_get_ex(json_in, "comments", &string_obj);
            const char *comments = json_object_get_string(string_obj);

            if ( comments != NULL )
                {

                    memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].comments, comments, BLUEDOT_COMMENTS);

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.comments");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", comments );

                    json_count++;
                }


            json_object_object_get_ex(json_in, "source", &string_obj);
            const char *source = json_object_get_string(string_obj);

            if ( source != NULL )
                {

                    memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].source, source, BLUEDOT_SOURCE);

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.source");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", source );

                    json_count++;
                }

            json_object_object_get_ex(json_in, "ctime", &string_obj);
            const char *ctime = json_object_get_string(string_obj);

            if ( ctime != NULL )
                {

                    memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].ctime, ctime, BLUEDOT_CTIME);

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.ctime");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", ctime );

                    json_count++;
                }

            json_object_object_get_ex(json_in, "mtime", &string_obj);
            const char *mtime = json_object_get_string(string_obj);

            if ( mtime != NULL )
                {

                    memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].mtime, mtime, BLUEDOT_MTIME);

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.mtime");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", mtime );

                    json_count++;

                }

            json_object_object_get_ex(json_in, "query", &string_obj);
            const char *query = json_object_get_string(string_obj);

            memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].query, query, BLUEDOT_QUERY);

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.query");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", query );

            json_count++;

            json_object_object_get_ex(json_in, "query_type", &string_obj);
            const char *query_type = json_object_get_string(string_obj);

            memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].query_type, query_type, BLUEDOT_QUERY_TYPE);

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.query_type");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", query_type );

            json_count++;

            json_object_object_get_ex(json_in, "last_seen", &string_obj);
            const char *last_seen = json_object_get_string(string_obj);

            if ( last_seen != NULL )
                {

                    memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].last_seen, last_seen, BLUEDOT_LAST_SEEN);

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.last_seen");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", last_seen );

                    json_count++;
                }

            json_object_object_get_ex(json_in, "query_counter", &string_obj);
            const char *query_counter = json_object_get_string(string_obj);

            BluedotIPCache[Counters->processor_bluedot_ip_cache].query_counter = atol( query_counter );

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.query_counter");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", query_counter );

            json_count++;

            json_object_object_get_ex(json_in, "counter", &string_obj);
            const char *counter = json_object_get_string(string_obj);

            BluedotIPCache[Counters->processor_bluedot_ip_cache].counter = atol( counter );

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.counter");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", counter );

            json_count++;

            snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.from_cache");
            snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", "false" );

            json_count++;

            // Counters->processors_bluedot_ip_total++ // STATS go here
            Counters->processor_bluedot_ip_cache++;

            pthread_mutex_unlock(&JAEBluedotIPWorkMutex);

        }

    json_object_put(json_in);                   /* Clear json_in as we're done with it */

    return(json_count);
}


/****************************************************************************
 * Bluedot_Clean_Queue - Clean's the "queue" of the type of lookup
 * that happened.  This is called after a successful lookup.  We do this to
 * prevent multiple lookups (at the same time!) of the same item!  This
 * happens a lot with IP address looks
 ****************************************************************************/

int Bluedot_Clean_Queue ( const char *json, uint8_t type )
{

    uint64_t i = 0;

    unsigned char ip_convert[MAX_IP_BIT_SIZE] = { 0 };

    if ( type == BLUEDOT_TYPE_IP && Config->processor_bluedot_ip_queue > 0 )
        {

            IP_2_Bit( (char*)json, ip_convert);

            for (i=0; i<Config->processor_bluedot_ip_queue; i++)
                {

                    if ( !memcmp(ip_convert, BluedotIPQueue[i].ip, MAX_IP_BIT_SIZE) )
                        {
                            memset(BluedotIPQueue[i].ip, 0, MAX_IP_BIT_SIZE);
                        }

                }

            __atomic_sub_fetch(&Counters->processor_bluedot_ip_queue, 1, __ATOMIC_SEQ_CST);

        }

    /*
        else if ( type == BLUEDOT_LOOKUP_HASH && config->bluedot_hash_max_cache > 0 )
            {

                for (i=0; i<config->bluedot_hash_queue; i++)
                    {

                        if ( !strcasecmp(json, SaganBluedotHashQueue[i].hash ) )
                            {

                                pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);
                                memset(SaganBluedotHashQueue[i].hash, 0, SHA256_HASH_SIZE+1);
                                pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);

                            }

                    }

                __atomic_sub_fetch(&counters->bluedot_hash_queue_current, 1, __ATOMIC_SEQ_CST);

            }

        else if ( type == BLUEDOT_LOOKUP_URL && config->bluedot_url_max_cache > 0 )
            {

                for (i =0; i<config->bluedot_url_queue; i++)
                    {

                        if ( !strcasecmp(json, SaganBluedotURLQueue[i].url ) )
                            {

                                pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);
                                memset(SaganBluedotURLQueue[i].url, 0, sizeof(SaganBluedotURLQueue[i].url));
                                pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);
                            }
                    }

                __atomic_sub_fetch(&counters->bluedot_url_queue_current, 1, __ATOMIC_SEQ_CST);

            }


        else if ( type == BLUEDOT_LOOKUP_FILENAME && config->bluedot_filename_max_cache > 0 )
            {

                for  (i=0; i<config->bluedot_filename_queue; i++)
                    {

                        if ( !strcasecmp(json, SaganBluedotFilenameQueue[i].filename ) )
                            {

                                pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);
                                memset(SaganBluedotFilenameQueue[i].filename, 0, sizeof(SaganBluedotFilenameQueue[i].filename));
                                pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);
                            }

                    }

                __atomic_sub_fetch(&counters->bluedot_filename_queue_current, 1, __ATOMIC_SEQ_CST);


            }

        else if ( type == BLUEDOT_LOOKUP_JA3 && config->bluedot_ja3_max_cache > 0 )
            {

                for  (i=0; i<config->bluedot_ja3_queue; i++)
                    {

                        if ( !strcasecmp(json, SaganBluedotJA3Queue[i].ja3 ) )
                            {

                                pthread_mutex_lock(&SaganProcBluedotJA3WorkMutex);
                                memset(SaganBluedotJA3Queue[i].ja3, 0, sizeof(SaganBluedotJA3Queue[i].ja3));
                                pthread_mutex_unlock(&SaganProcBluedotJA3WorkMutex);
                            }

                    }

                __atomic_sub_fetch(&counters->bluedot_ja3_queue_current, 1, __ATOMIC_SEQ_CST);

            }

    */

    return(true);
}


void Bluedot_Clean_Cache_Check(void)
{

    uint64_t current_time = GetEpochTime();

    if ( bluedot_cache_clean_lock == false && current_time > ( bluedot_last_time + Config->processor_bluedot_timeout ) )
        {

            pthread_mutex_lock(&BluedotWorkMutex);

            bluedot_cache_clean_lock = true;

            JAE_Log(NORMAL, "Bluedot cache timeout reached %d minutes.  Cleaning up.", Config->processor_bluedot_timeout / 60 );

            Bluedot_Clean_Cache();

            bluedot_cache_clean_lock = false;

            pthread_mutex_unlock(&BluedotWorkMutex);

        }

}


void Bluedot_Clean_Cache(void)
{

    /*
        uint64_t new_bluedot_ip_max_cache = 0;
        uint64_t new_bluedot_hash_max_cache = 0;
        uint64_t new_bluedot_url_max_cache = 0;
        uint64_t new_bluedot_filename_max_cache = 0;
        uint64_t new_bluedot_ja3_max_cache = 0;
        */

    uint64_t delete_count = 0;
    uint64_t i = 0;

    uint64_t current_time = GetEpochTime();

    uint64_t new_count = 0;

    /* Update last cleaning time! */

    bluedot_last_time = GetEpochTime();

    if (Debug->bluedot)
        {
            JAE_Log(DEBUG, "[%s, line %d] Bluedot cache clean time has been reached.", __FILE__, __LINE__);
            JAE_Log(DEBUG, "[%s, line %d] ----------------------------------------------------------------------", __FILE__, __LINE__);
        }

    struct _Bluedot_IP_Cache *TmpBluedotIPCache = NULL;

    TmpBluedotIPCache = malloc( Counters->processor_bluedot_ip_cache * sizeof(struct _Bluedot_IP_Cache));

    if ( TmpBluedotIPCache == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for TmpBluedotIPCache. Abort!", __FILE__, __LINE__);
        }

    memset(TmpBluedotIPCache, 0, Counters->processor_bluedot_ip_cache * sizeof(_Bluedot_IP_Cache));

    // Counters->processor_bluedot_memory_slot <- Number of slots.

    for (i=0; i < Counters->processor_bluedot_ip_cache; i++ )
        {

            if ( ( bluedot_last_time - BluedotIPCache[i].cache_utime ) > Config->processor_bluedot_timeout )
                {

                    memcpy(TmpBluedotIPCache[new_count].ip, BluedotIPCache[new_count].ip, MAX_IP_BIT_SIZE);
                    memcpy(TmpBluedotIPCache[new_count].ip_human, BluedotIPCache[new_count].ip_human, MAX_IP_BIT_SIZE);

                    TmpBluedotIPCache[new_count].mdate_utime = BluedotIPCache[new_count].mdate_utime;
                    TmpBluedotIPCache[new_count].cdate_utime = BluedotIPCache[new_count].cdate_utime;
                    TmpBluedotIPCache[new_count].cache_utime = BluedotIPCache[new_count].cache_utime;
                    TmpBluedotIPCache[new_count].code = BluedotIPCache[new_count].code;

                    new_count++;

                }

        }

    /* Adjust cache size */

    BluedotIPCache = (_Bluedot_IP_Cache *) realloc(BluedotIPCache, ( new_count + BLUEDOT_DEFAULT_MEMORY_SLOTS ) * sizeof(_Bluedot_IP_Cache));

    if ( BluedotIPCache == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for BluedotIPCache. Abort!", __FILE__, __LINE__);
        }


    /* Copy data to new cache array */

    for ( i = 0; i < new_count; i++ )
        {

            memcpy(BluedotIPCache[i].ip, TmpBluedotIPCache[i].ip, MAX_IP_BIT_SIZE);
            memcpy(BluedotIPCache[i].ip_human, TmpBluedotIPCache[i].ip_human, MAX_IP_BIT_SIZE);

            BluedotIPCache[i].mdate_utime = TmpBluedotIPCache[i].mdate_utime;
            BluedotIPCache[i].cdate_utime = TmpBluedotIPCache[i].cdate_utime;
            BluedotIPCache[i].cache_utime = TmpBluedotIPCache[i].cache_utime;
            BluedotIPCache[i].code = TmpBluedotIPCache[i].code;

        }

    free( TmpBluedotIPCache );

    Counters->processor_bluedot_ip_cache = new_count;
    Counters->processor_bluedot_memory_slot = new_count + BLUEDOT_DEFAULT_MEMORY_SLOTS;

//	Counters->processor_bluedot_memory_slot = Counters->processor_bluedot_memory_slot + BLUEDOT_DEFAULT_MEMORY_SLOTS;


}


uint16_t Check_IP_Cache ( struct _JSON_Key_String *JSON_Key_String, struct _Bluedot_Return *Bluedot_Return, uint16_t json_count, uint16_t json_position, unsigned char *ip_convert )
{


    uint64_t i = 0;

    for (i=0; i<Counters->processor_bluedot_ip_cache; i++)
        {

            if (!memcmp( ip_convert, BluedotIPCache[i].ip, MAX_IP_BIT_SIZE ))
                {

                    if (Debug->bluedot)
                        {
                            JAE_Log(DEBUG, "[%s, line %d] Pulled %s from BluedotIPCache with category of \"%s\" [code: %d, cdate_epoch: %d / mdate_epoch: %d]", __FILE__, __LINE__, JSON_Key_String[json_position].json, BluedotIPCache[i].category, BluedotIPCache[i].code, BluedotIPCache[i].cdate_utime, BluedotIPCache[i].mdate_utime);
                        }

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.mtime_epoch");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%" PRIu64 "", BluedotIPCache[i].mdate_utime );

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.ctime_epoch");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%" PRIu64 "", BluedotIPCache[i].cdate_utime );

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.api_user");
                    strlcpy(JSON_Key_String[json_count].json, BluedotIPCache[i].api_user, MAX_JSON_VALUE);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.code");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%" PRIu64 "", BluedotIPCache[i].code );

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.category");
                    strlcpy(JSON_Key_String[json_count].json, BluedotIPCache[i].category, MAX_JSON_VALUE);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.comments");
                    strlcpy(JSON_Key_String[json_count].json, BluedotIPCache[i].comments, MAX_JSON_VALUE);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.source");
                    strlcpy(JSON_Key_String[json_count].json, BluedotIPCache[i].source, MAX_JSON_VALUE);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.ctime");
                    strlcpy(JSON_Key_String[json_count].json, BluedotIPCache[i].ctime, MAX_JSON_VALUE);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.mtime");
                    strlcpy(JSON_Key_String[json_count].json, BluedotIPCache[i].mtime, MAX_JSON_VALUE);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.query");
                    strlcpy(JSON_Key_String[json_count].json, BluedotIPCache[i].query, MAX_JSON_VALUE);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.query_type");
                    strlcpy(JSON_Key_String[json_count].json, BluedotIPCache[i].query_type, MAX_JSON_VALUE);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.last_seen");
                    strlcpy(JSON_Key_String[json_count].json, BluedotIPCache[i].last_seen, MAX_JSON_VALUE);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.query_counter");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%" PRIu64 "", BluedotIPCache[i].query_counter);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.counter");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%" PRIu64 "", BluedotIPCache[i].counter);

                    json_count++;

                    snprintf(JSON_Key_String[json_count].key, MAX_JSON_KEY, ".bluedot.from_cache");
                    snprintf(JSON_Key_String[json_count].json, MAX_JSON_VALUE, "%s", "true" );

                    json_count++;

                    Bluedot_Return->code = BluedotIPCache[i].code;

                    return(json_count);
                }


        }

    return(json_count);

}

int8_t Bluedot_Category_Lookup( const char *category, char *str, size_t size )
{

    uint16_t i = 0;

    for ( i = 0; i < Counters->processors_bluedot_cat_count; i++ )
        {

            if ( !strcmp( BluedotCatList[i].category, category ) )
                {
                    snprintf( str, size, "%s", BluedotCatList[i].description);
                    return( BluedotCatList[i].code );
                }
        }

    return(-1);
}
