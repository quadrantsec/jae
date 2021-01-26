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


#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "rules.h"
#include "debug.h"
#include "counters.h"
#include "util-time.h"

#include "parsers/json.h"

#include "processors/bluedot.h"



struct _Rules *Rules;
struct _Debug *Debug;
struct _Config *Config;
struct _Counters *Counters;
struct _Bluedot_Skip *Bluedot_Skip;


struct _Bluedot_IP_Cache *BluedotIPCache = NULL;


pthread_mutex_t JAE_DNS_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t BluedotWorkMutex=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t JAEBluedotIPWorkMutex=PTHREAD_MUTEX_INITIALIZER;		// IP queue

struct _Bluedot_IP_Queue *BluedotIPQueue = NULL;

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
            /*
                        BluedotIPCache = malloc( BLUEDOT_DEFAULT_MEMORY_SLOTS * sizeof(struct _Bluedot_IP_Cache));

                        if ( BluedotIPCache == NULL )
                            {
                                JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Bluedot_IP_Cache. Abort!", __FILE__, __LINE__);
                            }

                        memset(BluedotIPCache, 0, BLUEDOT_DEFAULT_MEMORY_SLOTS * sizeof(_Bluedot_IP_Cache));

            	    Counters->processor_bluedot_memory_slot = BLUEDOT_DEFAULT_MEMORY_SLOTS;
            */
        }

}



uint16_t Bluedot_Add_JSON( struct _JSON_Key_String *JSON_Key_String, struct _Bluedot_Return *Bluedot_Return, uint16_t json_count, uint32_t rule_position, uint16_t json_position, uint8_t s_position )
{

    // use s_position to determine the nest depth!  bluedot.whatever.0

    int sockfd;
    struct sockaddr_in servaddr;

    struct json_object *json_in = NULL;
    struct json_object *string_obj = NULL;

    uint64_t i = 0;

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
            return(false);
        }

    /* Check DNS TTL,  do lookup if nessesary */
    /* DO LOOKUP in jae-config.c ( at start up !) */

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

    if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_IP )
        {

//            unsigned char ip_convert[MAX_IP_BIT_SIZE] = { 0 };

            IP_2_Bit(JSON_Key_String[json_position].json, ip_convert);

            /* Don't look up non-routed stuff */

            if ( Is_Not_Routable(ip_convert) || JSON_Key_String[json_position].json[0] == '0' )
                {

                    if ( Debug->bluedot )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, JSON_Key_String[json_position].json);
                        }

                    return(false);
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

                            return(false);
                        }

                }

            /* Check IP cache,  see if we already have the entry */

            for (i=0; i<Counters->processor_bluedot_ip_cache; i++)
                {

                    if (!memcmp( ip_convert, BluedotIPCache[i].ip, MAX_IP_BIT_SIZE ))
                        {

                            if (Debug->bluedot)
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] Pulled %s from Bluedot cache with category of \"%d\". [cdate_epoch: %d / mdate_epoch: %d]", __FILE__, __LINE__, JSON_Key_String[json_position].json, BluedotIPCache[i].code, BluedotIPCache[i].cdate_utime, BluedotIPCache[i].mdate_utime);
                                }


                            return(true);
                        }


                }



            /* Check IP queue */

            for ( i =0; i < Config->processor_bluedot_ip_queue; i++ )
                {

                    if ( !memcmp(ip_convert, BluedotIPQueue[i].ip, MAX_IP_BIT_SIZE ))
                        {
                            if (Debug->bluedot)
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] %s is already being looked up. Skipping....", __FILE__, __LINE__, JSON_Key_String[json_position].json);
                                }

                            return(false);
                        }

                }

            /* Make sure there is enough queue space! */

            if ( Counters->processor_bluedot_ip_queue >= Config->processor_bluedot_ip_queue )
                {
                    JAE_Log(NORMAL, "[%s, line %d] Out of IP queue space! Considering increasing cache size!", __FILE__, __LINE__);
                    return(false);
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

            snprintf(buff, sizeof(buff), "GET /%s%s%s HTTP/1.1\r\nHost: %s\r\n%s\r\nX-BLUEDOT-DEVICEID: %s\r\nConnection: close\r\n\r\n", Config->processor_bluedot_uri, BLUEDOT_IP_LOOKUP_URL, JSON_Key_String[json_position].json, Config->processor_bluedot_host, BLUEDOT_USER_AGENT, Config->processor_bluedot_device_id);

        }

    else if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_HASH )
        {

        }


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
            return(false);
        }


    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(Config->processor_bluedot_ip);
    servaddr.sin_port = htons(80);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
        {
            JAE_Log(WARN, "[%s, line %d] Unabled to connect to server %s!", __FILE__, __LINE__, Config->processor_bluedot_ip);
            // __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(false);
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
            return(false);
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
            return(false);
        }

    json_object_object_get_ex(json_in, "code", &string_obj);
    code = json_object_get_string(string_obj);

    if ( code == NULL )
        {
            JAE_Log(WARN, "Bluedot return a qipcode category.");
            //__atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(false);
        }

    code_u8 = atoi( code );
    Bluedot_Return->code = code_u8;

    /* IP addess specific codes (create time and modify time) */

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

    /* Do we have cache space? If not allocate more! */

    /* Add entries to cache */

    if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_IP )
        {

            pthread_mutex_lock(&JAEBluedotIPWorkMutex);

	    /* Allocate more memory if needed */

            if ( Counters->processor_bluedot_ip_cache >= Counters->processor_bluedot_memory_slot )
                {

                    Counters->processor_bluedot_memory_slot = Counters->processor_bluedot_memory_slot + BLUEDOT_DEFAULT_MEMORY_SLOTS;

                    printf("Allocatng : %d\n", Counters->processor_bluedot_memory_slot);

                    BluedotIPCache = (_Bluedot_IP_Cache *) realloc(BluedotIPCache, (Counters->processor_bluedot_memory_slot) * sizeof(_Bluedot_IP_Cache));

                    if ( BluedotIPCache == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for BluedotIPCache. Abort!", __FILE__, __LINE__);
                        }

                    printf("Cache is at %d\n", Counters->processor_bluedot_memory_slot);

                }

            memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].ip, ip_convert, MAX_IP_BIT_SIZE);
	    memcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].ip_human, JSON_Key_String[json_position].json, INET6_ADDRSTRLEN);
            //strlcpy(BluedotIPCache[Counters->processor_bluedot_ip_cache].json, json_final, sizeof(BluedotIPCache[Counters->processor_bluedot_ip_cache].json));
            BluedotIPCache[Counters->processor_bluedot_ip_cache].cache_utime = epoch_time;
            BluedotIPCache[Counters->processor_bluedot_ip_cache].cdate_utime = cdate_utime_u64;
            BluedotIPCache[Counters->processor_bluedot_ip_cache].mdate_utime = mdate_utime_u64;
            BluedotIPCache[Counters->processor_bluedot_ip_cache].code = code_u8;

            printf("Added %d to cache\n", Counters->processor_bluedot_ip_cache);

            // Counters->processors_bluedot_ip_total++ // STATS go here
            Counters->processor_bluedot_ip_cache++;

            pthread_mutex_unlock(&JAEBluedotIPWorkMutex);


        }

    json_object_put(json_in);                   /* Clear json_in as we're done with it */
    printf("at the end!\n");
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

            IP_2_Bit(json, ip_convert);

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


	printf("*** Old couunt: %d, New Count: %d\n", Counters->processor_bluedot_ip_cache,new_count);

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



