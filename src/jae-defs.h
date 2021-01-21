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

/***************************************************************************
 * Defaults
 ***************************************************************************/

#define		MAX_SENSOR_NAME			32
#define		MAX_CLUSTER_NAME		32


/***************************************************************************
 * Limits
 ***************************************************************************/

#define		MAX_JSON_SIZE			1048576
#define 	MAX_BATCH			100

#define		THREAD_NAME_LEN			16

#define		MAX_PATH			255

#define		MAX_CONFIG_LINE			32786

#define		MAX_JSON_KEY			512
#define		MAX_JSON_VALUE			32786
#define 	MAX_JSON_NEST		        1000

#define		MAX_HAYSTACK			32786
#define		MAX_NEEDLE			512

#define		MAX_IP_ADDRESS_SIZE		64
#define		MAX_IP_BIT_SIZE			16


#define		PARSE_IP_PRE			0
#define		PARSE_IP_POST			1

/***************************************************************************
 * For JAE_Log()
 ***************************************************************************/

#define NORMAL                  0
#define ERROR                   1
#define WARN                    2
#define DEBUG                   3

