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

#include <pcre.h>


#include "jae-defs.h"

#define 	MAX_IP_SIZE			64
#define		MAX_B64_SIG_SIZE		10240

//#define         VALID_RULE_OPTIONS "signature_id"

#define         MAX_RULE_SIZE                   4096	/* Largest size a signature can be */
#define		MAX_RULE_DESCRIPTION		256	/* Max "description" / human readable size */
#define		MAX_RULE_CLASSIFICATION		32	/* Max short "classification" size */
#define         MAX_RULE_CLASSIFICATION_DESC    96	/* Max long "classification size */
#define		MAX_RULE_REFERENCE		2048	/* Make URL length for a reference */

/* "search" and "exclude" definitions */

#define		MAX_RULE_SEARCH			10	/* Max "search" in a signature */
#define		MAX_RULE_SEARCH_MASK		512	/* Max size of a search mask */
#define		MAX_SEARCH_STRING		128	/* Max items in a search string */
#define		MAX_SEARCH_STRING_SIZE		256	/* Max size of individual searches */
#define		SEARCH_TYPE_EXACT		0	/* Default */
#define		SEARCH_TYPE_CONTAINS		1

/* "pcre" (regular expressions) definitions */

#define		MAX_PCRE			5	/* Max "pcre" within a signature */
#define		MAX_PCRE_SIZE			512	/* Max size of a regular expression */

/* "add_key" definitions */

#define		MAX_ADD_KEY			20
#define		MAX_ADD_KEY_SIZE		MAX_JSON_KEY		/* This should be JSON_MAX_KEY */
#define		MAX_ADD_KEY_VALUE_SIZE		MAX_JSON_VALUE		/* Same ^^^^ */

/* "parse_ip" definitions */

#define		MAX_PARSE_IP			5
#define		MAX_PARSE_IP_KEY_SIZE		MAX_JSON_KEY
#define		MAX_PARSE_IP_VALUE_SIZE		MAX_JSON_VALUE

/* "normalize" definitions */

#define		MAX_NORMALIZE			5
#define		MAX_NORMALIZE_KEY_SIZE		MAX_JSON_KEY

/* "bluedot" definitions */

#define		MAX_BLUEDOT			5
#define		MAX_BLUEDOT_KEY_SIZE		MAX_JSON_KEY


typedef struct _Rules _Rules;
struct _Rules
{

    uint64_t signature_id;
    uint16_t revision;
    char description[MAX_RULE_DESCRIPTION];
    char classification[MAX_RULE_CLASSIFICATION];
    char classification_desc[MAX_RULE_CLASSIFICATION_DESC];
    char reference[MAX_RULE_REFERENCE];

    char b64_signature_triggered[MAX_B64_SIG_SIZE];

    /* "search" and "exclude" specific options */

    char search_string[MAX_RULE_SEARCH][MAX_SEARCH_STRING][MAX_SEARCH_STRING_SIZE];

    uint8_t search_count[MAX_RULE_SEARCH];		/* Number of individual items to
    							   search.  It can be a list ["this",
							   "is","a","search"] or single item. */

    char search_key[MAX_RULE_SEARCH][MAX_JSON_KEY];
    bool search_type[MAX_RULE_SEARCH];
    bool search_case[MAX_RULE_SEARCH];
    bool search_not[MAX_RULE_SEARCH];
    char search_mask[MAX_RULE_SEARCH][MAX_RULE_SEARCH_MASK];

    uint8_t search_string_count;			/* Number of "search" requests. "search":
    							   { "0": { ... }, "1": { ... }} would be 2. */

    /* "pcre" (regular expression) options */

    uint8_t pcre_count;
    pcre *re_pcre[MAX_PCRE];
    pcre_extra *pcre_extra[MAX_PCRE];
    char pcre_key[MAX_PCRE][MAX_PCRE_SIZE];

    /* "add_key" */

    uint8_t add_key_count;
    char add_key_key[MAX_ADD_KEY][MAX_ADD_KEY_SIZE];
    char add_key_value[MAX_ADD_KEY][MAX_ADD_KEY_VALUE_SIZE];

    /* "parse_ip */

    uint8_t parse_ip_count;
    char parse_ip_key[MAX_PARSE_IP][MAX_PARSE_IP_KEY_SIZE];
    char parse_ip_store[MAX_PARSE_IP][MAX_PARSE_IP_VALUE_SIZE];
    uint8_t parse_ip_position[MAX_PARSE_IP];

    /* normalize */

    uint8_t normalize_count;
    char normalize_key[MAX_NORMALIZE][MAX_NORMALIZE_KEY_SIZE];

    /* bluedot */

    uint8_t bluedot_count;
    char bluedot_key[MAX_BLUEDOT][MAX_BLUEDOT_KEY_SIZE];
    uint8_t bluedot_type[MAX_BLUEDOT];
    bool bluedot_alert[MAX_BLUEDOT];
    uint8_t bluedot_match_count;



};


void Load_Ruleset( const char *ruleset );
