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

#include <stdbool.h>

void JAE_Log (int type, const char *format,... );
void To_LowerC(char *const s);
void Remove_Return(char *s);
void Remove_Spaces(char *s);
bool Validate_IP(const char *ip);
void Replace_String(char *in_str, char *orig, char *rep, char *str, size_t size);
void Droppriv(void);
void Between_Quotes(const char *in_str, char *str, size_t size);
bool Validate_HEX (const char *string);
bool Pipe_To_Value(const char *in_str, char *str, size_t size );
void Replace_JAE(const char *in_str, char *replace, char *str, size_t size);
void Var_To_Value(char *in_str, char *str, size_t size);

#ifdef __OpenBSD__
/* OpenBSD won't allow for this test:
 * "suricata(...): mprotect W^X violation" */
#ifndef PageSupportsRWX()
#define PageSupportsRWX() 0
#endif
#else
#ifndef HAVE_SYS_MMAN_H
#define PageSupportsRWX() 1
#else
int       PageSupportsRWX(void);
#endif /* HAVE_SYS_MMAN_H */
#endif


#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)
void Set_Pipe_Size ( FILE *fd );
#endif
