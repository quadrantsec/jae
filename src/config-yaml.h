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

/************************/
/* Minimum YAML version */
/************************/

#define YAML_VERSION_MAJOR 1
#define YAML_VERSION_MINOR 1

/*****************/
/* Primary types */
/*****************/

#define		YAML_TYPE_VAR		1
#define         YAML_TYPE_CORE          2
#define		YAML_TYPE_INPUT		3
#define         YAML_TYPE_OUTPUT        4
#define		YAML_TYPE_PROCESSORS	5
#define		YAML_TYPE_RULES		6
#define		YAML_TYPE_INCLUDES	7

/*************/
/* Sub Types */
/*************/

#define		YAML_SUBTYPE_INPUT_PIPE		1

#define		YAML_SUBTYPE_BLUEDOT		10

/**********************/
/* Sub type - outputs */
/**********************/

#define		YAML_SUBTYPE_OUTPUT_FILE	1


void Load_YAML_Config( const char * );
struct _Simple_Array *Comma_Delimited_Simple ( char *string );


