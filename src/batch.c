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

struct _Config *Config;

uint16_t batch_count = 0;
uint16_t processor_message_slot = 0;
uint16_t processor_running_threads = 0;

//char batch[MAX_BATCH][MAX_JSON_SIZE] = { 0 };


void Batch_Init( void )
{

    Input_Batch = malloc(Config->max_threads * sizeof(_Input_Batch));

    if ( Input_Batch == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Input_Batch. Abort!", __FILE__, __LINE__);
        }

    memset(Input_Batch, 0, sizeof(struct _Input_Batch));

}


void Batch( const char *input )
{

    if ( batch_count >= Config->batch_size )
        {

//	printf("Send to batch!\n");

            if ( processor_message_slot < Config->max_threads )
                {
//                    printf("Send work\n");

                    pthread_mutex_lock(&InputWorkMutex);

                    processor_message_slot++;

                    pthread_cond_signal(&InputDoWork);
                    pthread_mutex_unlock(&InputWorkMutex);

                }

            __atomic_store_n (&batch_count, 0, __ATOMIC_SEQ_CST);


        }

    strlcpy(Input_Batch[batch_count].input, input, MAX_JSON_SIZE);

    __atomic_add_fetch(&batch_count, 1, __ATOMIC_SEQ_CST);
//    printf("Batch is at: %d\n", batch_count);

}
