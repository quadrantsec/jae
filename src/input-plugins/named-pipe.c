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
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "version.h"
#include "jae-defs.h"
#include "jae.h"
#include "jae-config.h"
#include "counters.h"
#include "util.h"
#include "batch.h"


#include "input-plugins/named-pipe.h"

struct _Config *Config;
struct _Counters *Counters;
struct _Debug *Debug;

bool Global_Death;

void Input_Named_Pipe_Init(void)
{

    struct stat fifocheck;
    struct passwd *pw = NULL;

    pw = getpwnam(Config->runas);

    uint8_t ret = 0;

    if ( Config->input_named_pipe_chown == true )
        {
            JAE_Log(NORMAL, "Changing FIFO '%s' ownership to '%s'.", Config->input_named_pipe, Config->runas);

            ret = chown(Config->input_named_pipe, (unsigned long)pw->pw_uid,(unsigned long)pw->pw_gid);

            if ( ret < 0 )
                {
                    JAE_Log(ERROR, "[%s, line %d] Cannot change ownership of %s to username \"%s\" - %s", __FILE__, __LINE__, Config->input_named_pipe, Config->runas, strerror(errno));
                }

        }

}

void Input_Named_Pipe(void)
{

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("JAEnamedpipe");
#endif

    char *input = NULL;
    input = (char*)malloc( MAX_JSON_SIZE * sizeof(char) );  /* allocating memory dynamically  */

    bool pipe_error = false;
    FILE *fd;

    Input_Named_Pipe_Init();

    while( Global_Death == false )
        {

            if (( fd = fopen(Config->input_named_pipe, "r" )) == NULL )
                {
                    JAE_Log(ERROR, "[%s, line %d] Cannot open %s. %s.", __FILE__, __LINE__, Config->input_named_pipe, strerror(errno));
                }

            JAE_Log(NORMAL, "Successfully opened named pipe (%s).", Config->input_named_pipe);

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)
            Set_Pipe_Size(fd);
#endif

            while (fd != NULL )
                {

                    clearerr( fd );

                    while ( fgets( input, 1024, fd) != NULL )
                        {

                            __atomic_add_fetch(&Counters->input_received, 1, __ATOMIC_SEQ_CST);

                            if ( pipe_error == true )
                                {
                                    pipe_error = false;
                                    JAE_Log(NORMAL, "Named pipe writer has restarted. Processing events.");

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)
                                    Set_Pipe_Size(fd);
#endif
                                }

                            /* Send incoming message to queue/batch */

                            Batch( input );

                        } /* while(fgets) */

                    if ( pipe_error == false )
                        {
                            JAE_Log(WARN, "Named pipe writer closed.  Waiting for writer to restart....");
                            clearerr(fd);
                            pipe_error = true;   /* Set error flag for while(fgets) */
                        }

                    sleep(1);	/* So we don't eat 100% CPU */

                }

            fclose(fd);

        }  /* Global_Death */

    fclose(fd);
//	printf("GOT DEATH!\n");
    exit(0);

}
