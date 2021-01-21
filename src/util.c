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
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <grp.h>


#include "jae.h"
#include "util.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "var.h"
#include "counters.h"


struct _Config *Config;
struct _Counters *Counters;
struct _Var *Var;

/**********************************
 * Shift a string to all lowercase
 **********************************/

void To_LowerC(char *const s)
{
    char* cur = s;
    while (*cur)
        {
            *cur = tolower(*cur);
            ++cur;
        }
}


/******************************************************
 * Generic "jae.log" style logging and screen output.
 *******************************************************/

void JAE_Log (int type, const char *format,... )
{

    char buf[5128] = { 0 };
    va_list ap;
    va_start(ap, format);
    char *chr="*";
    char curtime[64];
    time_t t;
    struct tm *now;
    t = time(NULL);
    now=localtime(&t);
    strftime(curtime, sizeof(curtime), "%m/%d/%Y %H:%M:%S",  now);

    if ( type == ERROR )
        {
            chr="E";
        }

    if ( type == WARN )
        {
            chr="W";
        }

    if ( type == DEBUG )
        {
            chr="D";
        }

    vsnprintf(buf, sizeof(buf), format, ap);

    if ( Config->daemonize == 0 && Config->quiet == 0 )
        {
            printf("[%s] %s\n", chr, buf);
        }

    if ( type == ERROR )
        {
            exit(1);
        }

}

/********************
 * Remove new-lines
 ********************/

void Remove_Return(char *s)
{
    char *s1, *s2;
    for(s1 = s2 = s; *s1; *s1++ = *s2++ )
        while( *s2 == '\n' )s2++;
}

/***********************************************
 * Removes spaces from certain rule fields, etc
 ***********************************************/

void Remove_Spaces(char *s)
{
    char *s1, *s2;
    for(s1 = s2 = s; *s1; *s1++ = *s2++ )
        while( *s2 == ' ')s2++;
}


bool Validate_IP(const char *ip)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

/****************************************************************
 * String replacement function.  Used for things like $RULE_PATH
 ****************************************************************/

void Replace_String(char *in_str, char *orig, char *rep, char *str, size_t size)
{

    char buffer[4096] = { 0 };
    char *p = NULL;

    if(!(p = strstr(in_str, orig)))
        {
            snprintf(str, size, "%s", in_str);
            return;
        }

    strlcpy(buffer, in_str, p-in_str);
    buffer[p-in_str] = '\0';
    sprintf(buffer+(p-in_str), "%s%s", rep, p+strlen(orig));

    snprintf(str, size, "%s", buffer);

}

/****************************************************************************
 * Var_To_Value - Changes a variable in a configuration file (for
 * example - $RULE_PATH into it's true value.
 * ** README ** Don't use in live engine due to strstr.
 ****************************************************************************/

void Var_To_Value(char *in_str, char *str, size_t size)
{

    char *ptmp = NULL;
    char *tok = NULL;
    char tmp2[MAX_VAR_VALUE_SIZE] = { 0 };
    char tmp3[MAX_VAR_VALUE_SIZE] = { 0 };
    char tmp_result[MAX_VAR_VALUE_SIZE] = { 0 };
    char tmp[MAX_VAR_VALUE_SIZE] = { 0 };
    char tmp_quote[MAX_VAR_VALUE_SIZE] = { 0 };

    int i=0;

    snprintf(tmp, sizeof(tmp), "%s", in_str);           /* Segfault with strlcpy */

    for (i=0; i<Counters->var; i++)
        {

            ptmp = strtok_r(tmp, " ", &tok);

            while (ptmp != NULL )
                {
                    Replace_String(ptmp, Var[i].key, Var[i].value, tmp2, sizeof(tmp2));
                    snprintf(tmp3, sizeof(tmp3), "%s ", tmp2);
                    strlcat(tmp_result, tmp3, sizeof(tmp_result));
                    ptmp = strtok_r(NULL, " ", &tok);
                }

            strlcpy(tmp, tmp_result, sizeof(tmp));
            memset(tmp_result, 0, sizeof(tmp_result));
        }

    tmp[strlen(tmp)-1] = 0;             /* Remove trailing space */

    snprintf(str, size, "%s", tmp);

}

void Droppriv(void)
{

    struct stat fifocheck;
    struct passwd *pw = NULL;
    int ret;

    pw = getpwnam(Config->runas);

    if (!pw)
        {
            JAE_Log(ERROR, "Couldn't locate user '%s'. Aborting...", Config->runas);
        }

    if ( getuid() == 0 )
        {

            /*
             * We chown certain log files to our JAE user.  This is done so no files are "owned"
             * by "root".  This prevents problems in the future when doing things like handling
                 * SIGHUP's and what not.
                 *
                 * Champ Clark (04/14/2015)
                 */

//            if ( config->sagan_is_file == false )       /* Don't change ownsership/etc if we're processing a file */
//                {

            /*
                        if ( Config->named_pipe_chown == true )
                            {

                                JAE_Log(NORMAL, "Changing FIFO '%s' ownership to '%s'.", Config->named_pipe, Config->runas);

                                ret = chown(Config->named_pipe, (unsigned long)pw->pw_uid,(unsigned long)pw->pw_gid);

                                if ( ret < 0 )
                                    {
                                        JAE_Log(ERROR, "[%s, line %d] Cannot change ownership of %s to username \"%s\" - %s", __FILE__, __LINE__, Config->named_pipe, Config->runas, strerror(errno));
                                    }
                            }

            */


            JAE_Log(NORMAL, "Dropping privileges! [UID: %lu GID: %lu]", (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid);

            if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
                    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
                {
                    JAE_Log(ERROR, "[%s, line %d] Could not drop privileges to uid: %lu gid: %lu - %s!", __FILE__, __LINE__, (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid, strerror(errno));
                }

        }
    else
        {
            JAE_Log(NORMAL, "Not dropping privileges.  Already running as a non-privileged user");
        }
}


/****************************************************************************
 * Set_Pipe_Size - Changes the capacity of the pipe/FIFO.
 ****************************************************************************/

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)

void Set_Pipe_Size ( FILE *fd )
{

    uint8_t fd_int = 0;
    uint16_t current_fifo_size = 0;
    int8_t fd_results = 0;

    if ( Config->input_named_pipe_size != 0 )
        {

            fd_int = fileno(fd);
            current_fifo_size = fcntl(fd_int, F_GETPIPE_SZ);

            if ( current_fifo_size == Config->input_named_pipe_size )
                {

                    JAE_Log(NORMAL, "Named pipe capacity already set to %d bytes.", Config->input_named_pipe_size);

                }
            else
                {

                    JAE_Log(NORMAL, "Named pipe capacity is %d bytes.  Changing to %d bytes.", current_fifo_size, Config->input_named_pipe_size);

                    fd_results = fcntl(fd_int, F_SETPIPE_SZ, Config->input_named_pipe_size );

                    if ( fd_results == -1 )
                        {
                            JAE_Log(WARN, "Named pipe capacity could not be changed.  Continuing anyways...");
                        }

                    if ( fd_results > Config->input_named_pipe_size )
                        {
                            JAE_Log(WARN, "Named pipe  capacity was rounded up to the next page size of %d bytes.", fd_results);
                        }
                }
        }
}

#endif


void Between_Quotes(const char *in_str, char *str, size_t size)
{
    bool flag = false;
    uint16_t i = 0 ;

    char tmp1[2] = { 0 };
    char tmp2[MAX_JSON_VALUE] = { 0 };

    for ( i=0; i<strlen(in_str); i++)
        {

            if ( flag == true && in_str[i] == '\"' )
                {
                    flag = false;
                }

            if ( flag == true )
                {
                    snprintf(tmp1, sizeof(tmp1), "%c", in_str[i]);
                    strlcat(tmp2, tmp1, sizeof(tmp2));
                }

            if ( in_str[i] == '\"' ) flag = true;

        }

    snprintf(str, size, "%s", tmp2);
}

/****************************************************************************
 * Validate_HEX - Makes sure a string is valid hex.
 ****************************************************************************/

bool Validate_HEX (const char *string)
{

    const char *curr = string;

    while (*curr != 0)
        {
            if (('A' <= *curr && *curr <= 'F') || ('a' <= *curr && *curr <= 'f') || ('0' <= *curr && *curr <= '9'))
                {
                    ++curr;
                }
            else
                {
                    return(false);
                }
        }
    return(true);
}


bool Pipe_To_Value(const char *in_str, char *str, size_t size )
{

#define ALL_GOOD    0
#define BAD_VALUE   1
#define BAD_HEX	    2

    bool pipe_flag = false;

    /* Set to RULEBUF.  Some meta_content strings can be rather large! */

    char final_content[1024] = { 0 };
    char final_content_tmp[3] = { 0 };
    char tmp[2] = { 0 };

    uint16_t i = 0;
    int8_t x = 0;

    pipe_flag = false;

    for ( i=0; i<strlen(in_str); i++)
        {

            if ( in_str[i] == '|' && pipe_flag == 0 )
                {
                    pipe_flag = true;              /* First | has been found */
                }

            /* If we haven't found any |'s,  just copy the content verbatium */

            if ( pipe_flag == false )
                {
                    snprintf(final_content_tmp, sizeof(final_content_tmp), "%c", in_str[i]);
                    strncat(final_content, final_content_tmp, 1);
                }

            /* If | has been found,  start the conversion */

            if ( pipe_flag == true )
                {

                    if ( in_str[i+1] == ' ' || in_str[i+2] == ' ' )
                        {
                            return(BAD_VALUE);
                        }

                    snprintf(final_content_tmp, sizeof(final_content_tmp), "%c%c", in_str[i+1], in_str[i+2]);       /* Copy the hex value - ie 3a, 1B, etc */

                    if (!Validate_HEX(final_content_tmp))
                        {
                            return(BAD_HEX);
                        }

                    sscanf(final_content_tmp, "%x", &x);        /* Convert hex to dec */
                    snprintf(tmp, sizeof(tmp), "%c", x);        /* Convert dec to ASCII */
                    strncat(final_content, tmp, 1);             /* Append value */

                    /* Last | found,  but continue processing rest of content as normal */

                    if ( in_str[i+3] == '|' )
                        {
                            pipe_flag = false;
                            i=i+3;
                        }
                    else
                        {
                            i = i+2;
                        }
                }

        }

    snprintf(str, size, "%s", final_content);
    return(ALL_GOOD);

}

/****************************************************************************
 * Replace_JAE() - Take the %JAE% out of a string and replaces it
 * with *replace
 ****************************************************************************/

void Replace_JAE( const char *in_str, char *replace, char *str, size_t size )
{

    char tmp[2] = { 0 };
    char new_string[MAX_JSON_VALUE] = { 0 };

    uint16_t i = 0;

    for (i = 0; i < strlen(in_str); i++)
        {

            if ( in_str[i] == '%' )
                {

                    if ( in_str[i+1] == 'J' && in_str[i+2] == 'A' && in_str[i+3] == 'E' && in_str[i+4] == '%' )
                        {

                            strlcat(new_string, replace, sizeof(new_string));

                            i = i + 4;  /* Skip to end of %JAE% */

                        }
                    else
                        {

                            strlcat(new_string, "%", sizeof(new_string));
                        }
                }
            else
                {

                    snprintf(tmp, sizeof(tmp), "%c", in_str[i]);
                    strlcat(new_string, tmp, sizeof(new_string));

                }
        }


    snprintf(str, size, "%s", new_string);
}



/***************************************************************************
 * PageSupportsRWX - Checks the OS to see if it allows RMX pages.  This
 * function is from Suricata and is by Shawn Webb from HardenedBSD. GRSec
 * will cause things like PCRE JIT to fail.
 ***************************************************************************/

#ifndef HAVE_SYS_MMAN_H
#ifndef PageSupportsRWX
#define PageSupportsRWX 1
#endif
#else
#include <sys/mman.h>

int PageSupportsRWX(void)
{
    int retval = 1;
    void *ptr;
    ptr = mmap(0, getpagesize(), PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
    if (ptr != MAP_FAILED)
        {
            if (mprotect(ptr, getpagesize(), PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
                {
                    retval = 0;
                }
            munmap(ptr, getpagesize());
        }
    return retval;
}
#endif /* HAVE_SYS_MMAN_H */

