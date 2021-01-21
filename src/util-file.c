/*
** Copyright (C) 2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2020 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General                                        ** Public License.
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

/* util-file.c
 *
 * Simple file functions.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>

#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "config-yaml.h"
#include "util.h"
#include "util-file.h"
#include "lockfile.h"

#define  	BUF_SIZE	MAX_ITEM_SIZE

struct _Simple_Array *Load_Simple_File ( const char *filename )
{

    FILE *file;

    char buf[BUF_SIZE] = { 0 };

    uint64_t linecount = 0;
    uint64_t count = 0;

    struct _Simple_Array *Simple_Array = NULL;


    if (( file = fopen(filename, "r" )) == NULL )
        {
            Remove_Lock_File();
            JAE_Log(ERROR, "[%s, line %d] Cannot open file %s. [%s]", __FILE__,  __LINE__, filename, strerror(errno) );
        }

    while(fgets(buf, BUF_SIZE, file) != NULL)
        {

            linecount++;

            /* Skip comments and blank linkes */

            if (buf[0] == '#' || buf[0] == 10 || buf[0] == ';' || buf[0] == 32)
                {
                    continue;
                }

            Remove_Return(buf);

            Simple_Array = (_Simple_Array *) realloc(Simple_Array, (count+1) * sizeof(_Simple_Array));

            if ( Simple_Array == NULL )
                {
                    Remove_Lock_File();
                    JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Simple_Array.  Abort!", __FILE__, __LINE__);
                }

            memset(&Simple_Array[count], 0, sizeof(struct _Simple_Array));

            strlcpy(Simple_Array[count].item, buf, MAX_ITEM_SIZE);

            count++;

        }

    return( Simple_Array );

}
