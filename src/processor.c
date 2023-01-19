/* $Id$ */
/*
** Copyright (C) 2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2020 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or                                    ** distribute this program under any other version of the GNU General                                        ** Public License.                                                                                           **                                                                                                           ** This program is distributed in the hope that it will be useful,
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
#include <stdlib.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif


#include "jae-defs.h"
#include "jae.h"
#include "jae-config.h"
#include "batch.h"
#include "util.h"

#include "parsers/json.h"

#include "processors/engine.h"

extern struct _Config *Config;

extern bool Global_Death;

/* From batch.c */

extern struct _Input_Batch *Input_Batch;

extern uint16_t batch_count;
extern uint16_t processor_message_slot;
extern uint16_t processor_running_threads;

extern pthread_cond_t InputDoWork;
extern pthread_mutex_t InputWorkMutex;


void Processor (void)
{

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("JAEprocessor");
#endif

    uint16_t i = 0;
    uint16_t json_count = 0;

    struct _JSON_Key_String *JSON_Key_String;

    JSON_Key_String = malloc(sizeof(_JSON_Key_String) * MAX_JSON_NEST );

    if ( JSON_Key_String == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _JSON_Key_String", __FILE__, __LINE__);
        }

    struct _Input_Batch *Input_Batch_LOCAL;

    Input_Batch_LOCAL = malloc(Config->max_threads * sizeof(_Input_Batch));

    if ( Input_Batch_LOCAL == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Input_Batch_LOCAL. Abort!", __FILE__, __LINE__);
        }

    memset(Input_Batch_LOCAL, 0, sizeof(struct _Input_Batch));

    for ( i = 0; i < Config->batch_size; i++ )
        {
//      printf("init: %d\n", i);
        Input_Batch_LOCAL[i].input = malloc(MAX_JSON_SIZE);
        memset(Input_Batch_LOCAL[i].input, 0, MAX_JSON_SIZE);
//        printf("1: %d\n", sizeof(Input_Batch[i].input));
        }


    while (Global_Death == false )
        {

            pthread_mutex_lock(&InputWorkMutex);

            while ( processor_message_slot == 0 ) pthread_cond_wait(&InputDoWork, &InputWorkMutex);

            processor_message_slot--;
            processor_running_threads++;

            for ( i = 0; i < Config->batch_size; i++ )
                {

                    /* DEBUG STUFF HERE */

//			printf("size of: %d\n", sizeof( Input_Batch_LOCAL[i].input ) );
                    strlcpy(Input_Batch_LOCAL[i].input, Input_Batch[i].input, Config->max_json_size);
//		    strlcpy(Input_Batch_LOCAL[i].timestamp, Input_Batch[i].timestamp, sizeof(Input_Batch[i].timestamp));
                }

            pthread_mutex_unlock(&InputWorkMutex);

            __atomic_add_fetch(&processor_running_threads, 1, __ATOMIC_SEQ_CST);

            /* Process LOCAL data */

            for ( i = 0; i < Config->batch_size; i++ )
                {

                    json_count = Parse_JSON( Input_Batch_LOCAL[i].input, JSON_Key_String);

                    if ( json_count <= 1 )
                        {
                            JAE_Log(WARN, "[%s, line %d] Input doesn't appear to be JSON: %s", __FILE__, __LINE__, Input_Batch_LOCAL[i].input);
                        }


                    Engine( JSON_Key_String, json_count );

                }


            processor_running_threads--;
        }

    free(JSON_Key_String);

}
