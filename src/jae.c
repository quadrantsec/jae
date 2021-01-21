/*

Notes:

When using "exact", leading spaces get stripped.  So "   champtest" when searching
for "champtest" will get a hit.  But "this is a champtest" still won't

*/



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
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "version.h"
#include "jae-defs.h"
#include "jae.h"
#include "jae-config.h"
#include "counters.h"
#include "debug.h"
#include "lockfile.h"
#include "signal-handler.h"
#include "processor.h"
#include "batch.h"
#include "rules.h"
#include "classifications.h"
#include "config-yaml.h"


#include "parsers/json.h"
#include "parsers/normalize.h"
#include "parsers/strstr-asm/strstr-hook.h"

#include "input-plugins/named-pipe.h"

#include "output.h"
#include "output-plugins/file.h"

struct _Config *Config = NULL;
struct _Counters *Counters = NULL;
struct _Debug *Debug = NULL;

bool Global_Death = false;


int main(int argc, char **argv)
{

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("JAEmain");
#endif

    int8_t c = 0;
    uint8_t key = 0;
    uint8_t rc = 0;
    uint16_t i = 0;

    time_t t;
    struct tm *run;

    char tmp_time[16] = { 0 };

    /* Allocate memory for global struct _Config */

    Config = malloc(sizeof(_Config));

    if ( Config == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Config. Abort!", __FILE__, __LINE__);
        }

    memset(Config, 0, sizeof(_Config));

    /* Record the startup time */

    t = time(NULL);
    run=localtime(&t);
    strftime(tmp_time, sizeof(tmp_time), "%s",  run);

    Config->jae_start_time = atol( tmp_time );

    /* Allocate memory for global struct _Counters */

    Counters = malloc(sizeof(_Counters));

    if ( Counters == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Counters. Abort!", __FILE__, __LINE__);
        }

    memset(Counters, 0, sizeof(_Counters));

    /* Allocate memory for global struct _Debug */

    Debug = malloc(sizeof(_Debug));

    if ( Debug == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Debug. Abort!", __FILE__, __LINE__);
        }

    memset(Debug, 0, sizeof(_Debug));

    /**********************************************************************
     * Thread variables
    **********************************************************************/

    /* Block all signals,  we create a signal handling thread */

    sigset_t signal_set;
    pthread_t sig_thread;
    sigfillset( &signal_set );
    pthread_sigmask( SIG_BLOCK, &signal_set, NULL );

    /**********************************************************************
     * Defaults
     **********************************************************************/

    strlcpy(Config->config_yaml, CONFIG_FILE_PATH, sizeof(Config->config_yaml));   /* From config.h */

    /**********************************************************************
     * Command line
     **********************************************************************/

    const struct option long_options[] =
    {
        { "help",         no_argument,          NULL,   'h' },
        { "debug",        required_argument,    NULL,   'd' },
        { "daemon",       no_argument,          NULL,   'D' },
        { "user",         required_argument,    NULL,   'u' },
        { "chroot",       required_argument,    NULL,   'C' },
        { "credits",      no_argument,          NULL,   'X' },
        { "config",       required_argument,    NULL,   'c' },
        { "log",          required_argument,    NULL,   'l' },
        { "quiet",        no_argument,          NULL,   'q' },
        {0, 0, 0, 0}
    };

    static const char *short_options =
        "l:f:u:d:c:pDhCQ";

    int option_index = 0;

    /* "systemd" wants to start JAE in the foreground,  but doesn't know what to
     * do with stdin/stdout.  Hence,  CPU goes to 100%.  This detects our terminal
     * type ( >/dev/null </dev/null ) and tell's JAE to ignore input and output.
     *
     * For more details, see:
     *
     * https://groups.google.com/forum/#!topic/sagan-users/kgJvf1eyQcg
     *
     */

    if ( !isatty(0) || !isatty(1) || !isatty(2) )
        {
            Config->quiet = true;
        }

    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {

            switch(c)
                {

                case 'h':
                    //               Usage();
                    exit(0);
                    break;

                case 'C':
                    //              Credits();
                    exit(0);
                    break;

                case 'q':
                    Config->quiet = true;
                    break;

                case 'D':
                    Config->daemonize = true;
                    Config->quiet = true;
                    break;

                case 'd':

                    if (JAE_strstr(optarg, "config"))
                        {
                            Debug->config = true;
                        }

                    if (JAE_strstr(optarg, "rules"))
                        {
                            Debug->rules = true;
                        }

                    if (JAE_strstr(optarg, "parse_ip"))
                        {
                            Debug->parse_ip = true;
                        }

                    if (JAE_strstr(optarg, "bluedot"))
                        {
                            Debug->bluedot = true;
                        }


                    break;


                default:
                    fprintf(stderr, "Invalid argument! See below for command line switches.\n");
                    //             Usage();
                    exit(0);
                    break;

                }
        }

    /* NOTE: Open log file here */

    if ( Config->daemonize )
        {

            JAE_Log(NORMAL, "Becoming a daemon!");

            pid_t pid = 0;
            pid = fork();

            if ( pid == 0 )
                {

                    /* Child */

                    if ( setsid() == -1 )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Failed creating new session while daemonizing", __FILE__, __LINE__);
                            exit(1);
                        }

                    pid = fork();

                    if ( pid == 0 )
                        {

                            /* Grandchild, the actual daemon */

                            if ( chdir("/") == -1 )
                                {
                                    JAE_Log(ERROR, "[%s, line %d] Failed changing directory to / after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                    exit(1);
                                }

                            /* Close and re-open stdin, stdout, and stderr, so as to
                               to release anyone waiting on them. */

                            close(0);
                            close(1);
                            close(2);

                            if ( open("/dev/null", O_RDONLY) == -1 )
                                {
                                    JAE_Log(ERROR, "[%s, line %d] Failed reopening stdin after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_WRONLY) == -1 )
                                {
                                    JAE_Log(ERROR, "[%s, line %d] Failed reopening stdout after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_RDWR) == -1 )
                                {
                                    JAE_Log(ERROR, "[%s, line %d] Failed reopening stderr after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                        }
                    else if ( pid < 0 )
                        {

                            JAE_Log(ERROR, "[%s, line %d] Failed second fork while daemonizing", __FILE__, __LINE__);
                            exit(1);

                        }
                    else
                        {

                            exit(0);
                        }

                }
            else if ( pid < 0 )
                {

                    JAE_Log(ERROR, "[%s, line %d] Failed first fork while daemonizing", __FILE__, __LINE__);
                    exit(1);

                }
            else
                {

                    /* Wait for child to exit */
                    waitpid(pid, NULL, 0);
                    exit(0);
                }
        }

#ifdef PCRE_HAVE_JIT

    /* We test if pages will support RWX before loading rules.  If it doesn't due to the OS,
       we want to disable PCRE JIT now.  This prevents confusing warnings of PCRE JIT during
       rule load */

    Config->pcre_jit = true;

    if (PageSupportsRWX() == false)
        {
            JAE_Log(WARN, "The operating system doens't allow RWX pages.  Disabling PCRE JIT.");
            Config->pcre_jit = false;
        }

#endif


    Load_YAML_Config( Config->config_yaml );
    Load_Normalize();

    CheckLockFile();

    if ( Config->processor_bluedot_flag == true )
        {

            Bluedot_Init();

            bool res = DNS_Lookup( Config->processor_bluedot_host, Config->processor_bluedot_ip, sizeof(Config->processor_bluedot_ip) );

            if ( res == false )
                {
                    Remove_Lock_File();
                    JAE_Log(ERROR, "[%s, line %d] DNS lookup failure for host \"%s\". Abort!", __FILE__, __LINE__, Config->processor_bluedot_host );
                }

            Config->processor_bluedot_dns_last_lookup = Config->jae_start_time;

            JAE_Log(NORMAL, "Bluedot host \"%s\" is at %s", Config->processor_bluedot_host, Config->processor_bluedot_ip );

        }


    /* Init _Output_ */

//    Init_Output();

//    Droppriv();              /* Become the JAE user */


    /************************************************************************
     * Signal handler thread
     ************************************************************************/

    rc = pthread_create( &sig_thread, NULL, (void *)Signal_Handler, NULL );

    if ( rc != 0  )
        {
            Remove_Lock_File();
            JAE_Log(ERROR, "[%s, line %d] Error creating Signal_Handler thread. [error: %d]", __FILE__, __LINE__, rc);
        }

    /* Init batch queue */

    Batch_Init();

    /* Main processor! */

    pthread_t processor_id[Config->max_threads];
    pthread_attr_t thread_processor_attr;
    pthread_attr_init(&thread_processor_attr);
    pthread_attr_setdetachstate(&thread_processor_attr,  PTHREAD_CREATE_DETACHED);

    JAE_Log(NORMAL, "Spawning %d Processor Threads.", Config->max_threads);

    for (i = 0; i < Config->max_threads; i++)
        {

            rc = pthread_create ( &processor_id[i], &thread_processor_attr, (void *)Processor, NULL );

            if ( rc != 0 )
                {

                    Remove_Lock_File();
                    JAE_Log(ERROR, "Could not create Processor threads. [error: %d]", rc);

                }
        }

    /* Spawn _input_ threads */

    if ( Config->input_named_pipe_flag == true )
        {

            pthread_t named_pipe_thread;
            pthread_attr_t thread_named_pipe_attr;
            pthread_attr_init(&thread_named_pipe_attr);
            pthread_attr_setdetachstate(&thread_named_pipe_attr,  PTHREAD_CREATE_DETACHED);

            rc = pthread_create( &named_pipe_thread, NULL, (void *)Input_Named_Pipe, NULL );

            if ( rc != 0  )
                {
                    Remove_Lock_File();
                    JAE_Log(ERROR, "[%s, line %d] Error creating Input_Named_Pipe thread. [error: %d]", __FILE__, __LINE__, rc);
                }

        }

    Droppriv();

    //Load_Normalize();
    Init_Output();

    while( Global_Death == false)
        {


            if ( Config->daemonize == false )
                {

                    key=getchar();

                    if ( key != 0 )
                        {
                            //Statistics();
                            printf("Got key\n");
                        }

                }
            else
                {

                    /* Prevents eating CPU when in background! */

                    sleep(1);
                }

        }

}
