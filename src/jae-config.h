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


#include <stdint.h>
#include <stdbool.h>

/* JAE configuration struct (global) */

typedef struct _Config _Config;
struct _Config
{

    /***********************************************************************/
    /* Non-dependent var's                                                 */
    /***********************************************************************/

    bool         daemonize;
    bool         quiet;
    bool	 pcre_jit;

    char 	 config_yaml[MAX_PATH];
    uint64_t	 jae_start_time;

    /***********************************************************************/
    /* Configuration 							   */
    /***********************************************************************/

    char		runas[32];

    char		sensor_name[MAX_SENSOR_NAME];
    char		cluster_name[MAX_CLUSTER_NAME];

    uint32_t		max_threads;
    unsigned char	batch_size;
    char	        classifications_file[MAX_PATH];
    char		reference_file[MAX_PATH];
    char		normalize_file[MAX_PATH];
    char		lock_file[MAX_PATH];
    char		lock_file_path[MAX_PATH];
    bool		parse_ip;

    /***********************************************************************/
    /* Input								   */
    /***********************************************************************/

    /* named pipe */

    bool input_named_pipe_flag;
    char input_named_pipe[MAX_PATH];
    uint32_t input_named_pipe_size;
    bool input_named_pipe_chown;


    /***********************************************************************/
    /* Output                                                              */
    /***********************************************************************/

    bool output_file_flag;
    char output_file[MAX_PATH];
    bool output_file_flatten_json;
    bool output_file_append_alert_data;
//    FILE *output_file_stream;

    /***********************************************************************/
    /* Bluedot                                                             */
    /***********************************************************************/

    bool processor_bluedot_flag;
    char processor_bluedot_device_id[64];
    uint32_t processor_bluedot_timeout;
    char processor_bluedot_host[255];
    uint32_t processor_bluedot_dns_ttl;
    char processor_bluedot_uri[1024];
    uint64_t processor_bluedot_dns_last_lookup;
    char processor_bluedot_ip[64];

    uint16_t processor_bluedot_ip_queue;
    uint16_t processor_bluedot_hash_queue;
    uint16_t processor_bluedot_url_queue;
    uint16_t processor_bluedot_filename_queue;
    uint16_t processor_bluedot_ja3_queue;







};
