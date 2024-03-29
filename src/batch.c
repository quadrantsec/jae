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
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>


#include "version.h"
#include "jae-defs.h"
#include "jae.h"
#include "jae-config.h"
#include "counters.h"
#include "batch.h"

pthread_cond_t InputDoWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t InputWorkMutex=PTHREAD_MUTEX_INITIALIZER;

struct _Input_Batch *Input_Batch = NULL;

extern struct _Config *Config;

uint16_t batch_count = 0;
uint16_t processor_message_slot = 0;
uint16_t processor_running_threads = 0;

//char batch[MAX_BATCH][MAX_JSON_SIZE] = { 0 };


void Batch_Init( void )
{

uint16_t i = 0; 


    Input_Batch = malloc(Config->max_threads * sizeof(_Input_Batch) );

    if ( Input_Batch == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Input_Batch. Abort!", __FILE__, __LINE__);
        }

    memset(Input_Batch, 0, sizeof(struct _Input_Batch));

    for ( i = 0; i < Config->batch_size; i++ )
	{
//	printf("init: %d\n", i);
	Input_Batch[i].input = malloc( Config->max_json_size ); 
	memset(Input_Batch[i].input, 0, Config->max_json_size );
//        printf("1: %d\n", sizeof(Input_Batch[i].input));
	}

}


void Batch( const char *input )
{

//    struct timeval timestamp;
//    char batch_timestamp[64] = { 0 };

    if ( batch_count >= Config->batch_size )
        {

	printf("Send to batch!\n");

            if ( processor_message_slot < Config->max_threads )
                {
                    printf("Send work\n");

                    pthread_mutex_lock(&InputWorkMutex);

                    processor_message_slot++;

                    pthread_cond_signal(&InputDoWork);
                    pthread_mutex_unlock(&InputWorkMutex);

                }

            __atomic_store_n (&batch_count, 0, __ATOMIC_SEQ_CST);


        }

    printf("INPUT: %s\n", input);

    strlcpy(Input_Batch[batch_count].input, input, Config->max_json_size);

//    gettimeofday(&timestamp, 0);       /* Store event batch time */
//    CreateIsoTimeString(&timestamp, Input_Batch[batch_count].timestamp, sizeof(Input_Batch[batch_count].timestamp));

    __atomic_add_fetch(&batch_count, 1, __ATOMIC_SEQ_CST);
    printf("Batch is at: %d\n", batch_count);

}
