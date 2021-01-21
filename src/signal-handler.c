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
** This program is distributed in the hope that it will be useful,                                           ** but WITHOUT ANY WARRANTY; without even the implied warranty of
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
#include <signal.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "version.h"
#include "jae.h"
#include "jae-defs.h"
#include "util.h"
#include "lockfile.h"

bool Global_Death;


void Signal_Handler( void )
{

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("JAEsignal");
#endif

    sigset_t signal_set;
    uint32_t sig;

    for(;;)
        {
            /* wait for any and all signals */

            sigfillset( &signal_set );
            sigwait( &signal_set, &sig );

            switch( sig )
                {
                /* exit */
                case SIGQUIT:
                case SIGINT:
                case SIGTERM:
                case SIGSEGV:
                case SIGABRT:

                    Global_Death = true;


                    JAE_Log(NORMAL, "\n\n[Received signal %d. JAE version %s shutting down]-------\n", sig, VERSION);

                    Remove_Lock_File();
                    exit(0);
                    break;


                default:
                    JAE_Log(NORMAL, "[Received signal %d. Sagan doesn't know how to deal with]", sig);

                }

        }

}

