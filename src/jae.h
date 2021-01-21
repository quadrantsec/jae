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

#include <string.h>
#include <errno.h>

#include "util.h"

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t );
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t );
#endif

/*
 * OS specific macro's for setting the thread name. "top" can display
 * this name. This was largely taken from Suricata.
 */

#if defined __FreeBSD__ /* FreeBSD */
/** \todo Add implementation for FreeBSD */
#define SetThreadName(n) ({ \
    char tname[16] = ""; \
    if (strlen(n) > 16) \
        JAE_Log(WARN, "Thread name is too long, truncating it..."); \
    strlcpy(tname, n, 16); \
    pthread_set_name_np(pthread_self(), tname); \
    0; \
})
#elif defined __OpenBSD__ /* OpenBSD */
/** \todo Add implementation for OpenBSD */
#define SetThreadName(n) (0)
#elif defined OS_WIN32 /* Windows */
/** \todo Add implementation for Windows */
#define SetThreadName(n) (0)
#elif defined OS_DARWIN /* Mac OS X */
/** \todo Add implementation for MacOS */
#define SetThreadName(n) (0)
#elif defined HAVE_SYS_PRCTL_H /* PR_SET_NAME */
/**
 * \brief Set the threads name
 */
#define SetThreadName(n) ({ \
    char tname[THREAD_NAME_LEN + 1] = ""; \
    if (strlen(n) > THREAD_NAME_LEN) \
        JAE_Log(WARN, "Thread name is too long, truncating it..."); \
    strlcpy(tname, n, THREAD_NAME_LEN); \
    int ret = 0; \
    if ((ret = prctl(PR_SET_NAME, tname, 0, 0, 0)) < 0) \
        JAE_Log(WARN, "Error setting thread name \"%s\": %s", tname, strerror(errno)); \
    ret; \
})
#else
#define SetThreadName(n) (0)
#endif

