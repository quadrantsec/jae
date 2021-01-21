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
#include <errno.h>
//#include <json.h>

#include "jae-defs.h"
#include "jae.h"
#include "jae-config.h"
#include "rules.h"
#include "lockfile.h"

#include "parsers/json.h"

struct _Config *Config;


void File_Init( void )
{

    FILE *test_stream;

    if (( test_stream = fopen(Config->output_file, "a" )) == NULL )
        {
            Remove_Lock_File();
            JAE_Log(ERROR, "[%s, line %d] Can't for 'file' output %s - %s. Abort.", __FILE__, __LINE__, Config->output_file, strerror(errno));
        }

    JAE_Log(NORMAL, "Successfully open %s for 'file' output.", Config->output_file);
    fclose(test_stream);

}

void File( const char *output_json )
{

    /* NEEDS FILE LOCKING */

    FILE *output_stream;

    if (( output_stream = fopen(Config->output_file, "a" )) == NULL )
        {
            Remove_Lock_File();
            JAE_Log(ERROR, "[%s, line %d] Can't for 'file' output %s - %s. Abort.", __FILE__, __LINE__, Config->output_file, strerror(errno));
        }

    fprintf(output_stream, "%s\n", output_json);
    fclose(output_stream);


}
