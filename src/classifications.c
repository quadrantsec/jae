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

/* classifications.c
 *
 * Loads the classifications file into memory for future use.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#include "version.h"

#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "rules.h"
#include "classifications.h"
#include "counters.h"
#include "debug.h"

struct _Counters *Counters;
struct _Debug *Debug;
struct _Counters *Counters;
struct _Config *Config;

struct _Classifications *Classifications = NULL;


void Load_Classifications( void )
{

    FILE *classfile;

    char classbuf[128] = { 0 };

    char *saveptr=NULL;
    char *tmptoken=NULL;
    char *laststring=NULL;

    char tmpbuf2[5] = { 0 };

    uint16_t  linecount=0;

    __atomic_store_n (&Counters->classifications, 0, __ATOMIC_SEQ_CST);

    JAE_Log(NORMAL, "Loading classifications.conf file. [%s]", Config->classifications_file);

    if (( classfile = fopen(Config->classifications_file, "r" )) == NULL )
        {
            JAE_Log(ERROR, "[%s, line %d] Cannot open rule file %s. [%s]", __FILE__,  __LINE__, Config->classifications_file, strerror(errno) );
        }

    while(fgets(classbuf, sizeof(classbuf), classfile) != NULL)
        {

            linecount++;

            /* Skip comments and blank linkes */

            if (classbuf[0] == '#' || classbuf[0] == 10 || classbuf[0] == ';' || classbuf[0] == 32)
                {
                    continue;
                }

            /* Allocate memory for classifications,  but not comments */

            Classifications = (_Classifications *) realloc(Classifications, (Counters->classifications+1) * sizeof(_Classifications));

            if ( Classifications == NULL )
                {
                    JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Classifications. Abort!", __FILE__, __LINE__);
                }

            memset(&Classifications[Counters->classifications], 0, sizeof(struct _Classifications));

            strtok_r(classbuf, ":", &saveptr);
            tmptoken = strtok_r(NULL, ":", &saveptr);

            laststring = strtok_r(tmptoken, ",", &saveptr);

            if ( laststring == NULL )
                {
                    JAE_Log(ERROR, "[%s, line %d] The file %s at line %d is improperly formated. Abort!", __FILE__, __LINE__, Config->classifications_file, linecount);
                }

            Remove_Spaces(laststring);
            strlcpy(Classifications[Counters->classifications].shortname, laststring, sizeof(Classifications[Counters->classifications].shortname));

            laststring = strtok_r(NULL, ",", &saveptr);

            if ( laststring == NULL )
                {
                    JAE_Log(ERROR, "[%s, line %d] The file %s at line %d is improperly formated. Abort!", __FILE__, __LINE__, Config->classifications_file, linecount);
                }

            strlcpy(Classifications[Counters->classifications].desc, laststring, sizeof(Classifications[Counters->classifications].desc));

            laststring = strtok_r(NULL, ",", &saveptr);

            if ( laststring == NULL )
                {
                    JAE_Log(ERROR, "[%s, line %d] The file %s at line %d is improperly formated. Abort!", __FILE__, __LINE__, Config->classifications_file, linecount);
                }

            strlcpy(tmpbuf2, laststring, sizeof(tmpbuf2));
            Classifications[Counters->classifications].priority=atoi(tmpbuf2);

            if ( Classifications[Counters->classifications].priority == 0 )
                {
                    JAE_Log(ERROR, "[%s, line %d] Classification error at line number %d in %s", __FILE__, __LINE__, linecount, Config->classifications_file);
                }

            /*
                        if (debug->debugload)
                            {
                                JAE_Log(DEBUG, "[D-%d] Classification: %s|%s|%d", Counters->classifications, Classifications[Counters->classifications].shortname, Classifications[Counters->classifications].desc, Classifications[Counters->classifications].priority);
                            }
            */

            __atomic_add_fetch(&Counters->classifications, 1, __ATOMIC_SEQ_CST);

        }
    fclose(classfile);

    JAE_Log(NORMAL, "%d classifications loaded", Counters->classifications);

}

/****************************************************************************
 * Classtype_Lookup - Simple routine that looks up the classtype
 * (shortname) and returns the classtype's description
 ****************************************************************************/

int16_t Classtype_Lookup( const char *classtype, char *str, size_t size )
{

    uint16_t i = 0;

    for (i = 0; i < Counters->classifications; i++)
        {

            if (!strcmp(classtype, Classifications[i].shortname))
                {
                    snprintf(str, size, "%s", Classifications[i].desc);
                    return 0;
                }
        }

    snprintf(str, sizeof("UNKNOWN"), "UNKNOWN");
    return -1;
}


