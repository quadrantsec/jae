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

#include "processors/bluedot.h"

struct _Rules *Rules;
struct _Debug *Debug;
struct _Config *Config;
struct _Counters *Counters;
struct _Bluedot_Skip *Bluedot_Skip;

pthread_mutex_t JAE_DNS_Mutex=PTHREAD_MUTEX_INITIALIZER;


pthread_mutex_t JAEBluedotIPWorkMutex=PTHREAD_MUTEX_INITIALIZER;		// IP queue

struct _Bluedot_IP_Queue *BluedotIPQueue = NULL;

bool bluedot_dns_global = 0;

void Bluedot_Init( void )
{

    /* IP Queue */

    if ( Config->processor_bluedot_ip_queue > 0 )
        {

            BluedotIPQueue = malloc(Config->processor_bluedot_ip_queue * sizeof(struct _Bluedot_IP_Queue));

            if ( BluedotIPQueue == NULL )
                {
                    JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Bluedot_IP_Queue. Abort!", __FILE__, __LINE__);
                }

            memset(BluedotIPQueue, 0, Config->processor_bluedot_ip_queue * sizeof(_Bluedot_IP_Queue));
        }

}


bool Bluedot( uint32_t rule_position, uint8_t s_position, char *json )
{

    char timet[20] = { 0 };
    time_t t;
    struct tm *now=NULL;

    int sockfd;
    struct sockaddr_in servaddr;

    struct json_object *json_in = NULL;
    struct json_object *string_obj = NULL;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    uint64_t epoch_time = atol(timet);
    uint64_t i = 0;

    char buff[1024] = { 0 }; 

    char *jsonptr = NULL;
    char *jsonptr_f = NULL;
    char json_final[1024] = { 0 }; 

        const char *cdate_utime = NULL;
        uint32_t cdate_utime_u32 = 0;
        
        const char *mdate_utime = NULL;
        uint32_t mdate_utime_u32 = 0;


    /* If we have "NOT_FOUND", we can skip this */

    if ( json[0] == 'N' )
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

            unsigned char ip_convert[MAX_IP_BIT_SIZE] = { 0 };

            IP_2_Bit(json, ip_convert);

            /* Don't look up non-routed stuff */

            if ( Is_Not_Routable(ip_convert) || !strcmp(json, "0.0.0.0" ) )
                {

                    if ( Debug->bluedot )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, json);
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
                                    JAE_Log(DEBUG, "[%s, line %d] IP address %s is in Bluedot 'skip_networks'. Skipping lookup.", __FILE__, __LINE__, json);
                                }

                            return(false);
                        }

                }

	    /* Check cache */

	    for ( i =0; i < Config->processor_bluedot_ip_queue; i++ )
	    	{

			if ( !memcmp(ip_convert, BluedotIPQueue[i].ip, MAX_IP_BIT_SIZE ))
                        {
                            if (Debug->bluedot)
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] %s is already being looked up. Skipping....", __FILE__, __LINE__, json);
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

		snprintf(buff, sizeof(buff), "GET /%s%s%s HTTP/1.1\r\nHost: %s\r\n%s\r\nX-BLUEDOT-DEVICEID: %s\r\nConnection: close\r\n\r\n", Config->processor_bluedot_uri, BLUEDOT_IP_LOOKUP_URL, json, Config->processor_bluedot_host, BLUEDOT_USER_AGENT, Config->processor_bluedot_device_id);

        }

	else if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_HASH )
	{

	}


	/* Do the lookup! */

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
            JAE_Log(WARN, "[%s, %d] Unabled to connect to server %s!", __FILE__, __LINE__, Config->processor_bluedot_ip);
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

    printf("||%s||\n", json_final);

    json_in = json_tokener_parse(json_final);

    if ( json_in == NULL )
        {
            JAE_Log(WARN, "[%s, line %d] Unable to parse Bluedot JSON: %s", __FILE__, __LINE__, json_final);
           // __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(false);
        }



/* IP addess specific codes (create time and modify time) */

if ( Rules[rule_position].bluedot_type[s_position] == BLUEDOT_TYPE_IP )
        {

	json_object_object_get_ex(json_in, "ctime_epoch", &string_obj);
	cdate_utime = json_object_get_string(string_obj);

            if ( cdate_utime != NULL )
                {
                    cdate_utime_u32 = atol(cdate_utime);
                }
            else
                {
                    JAE_Log(WARN, "Bluedot return a bad ctime_epoch.");
                }

	    json_object_object_get_ex(json_in, "mtime_epoch", &string_obj);
	    mdate_utime = json_object_get_string(string_obj);

            if ( mdate_utime != NULL )
                {
                    mdate_utime_u32 = atol(mdate_utime);
                }
            else
                {
                    JAE_Log(WARN, "Bluedot return a bad mdate_epoch.");
                }

	}


	const char *code = NULL; 
	uint8_t code_u8 = 0; 

        json_object_object_get_ex(json_in, "code", &string_obj);
        code = json_object_get_string(string_obj);

    if ( code == NULL )
        {
            JAE_Log(WARN, "Bluedot return a qipcode category.");
//            __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(false);
        }

	code_u8 = atoi( code );

	json_object_put(json_in);                   /* Clear json_in as we're done with it */

	if ( code_u8 > 0 ) 
		{
		return(true);
		}


return(false);
}
