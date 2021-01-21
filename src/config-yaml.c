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


/* NOTES:

   NO DEFAULTS BEING SET.  Check things like "is cluster name" there?  More
   sanity checks

*/


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <libgen.h>

#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"
#include "config-yaml.h"
#include "util.h"
#include "util-file.h"
#include "var.h"
#include "counters.h"
#include "debug.h"
#include "rules.h"
#include "classifications.h"

#include "processors/bluedot.h"

#include "parsers/strstr-asm/strstr-hook.h"

#ifdef HAVE_LIBYAML
#include <yaml.h>
#endif

#ifndef HAVE_LIBYAML
libyaml is required.  Get it from your distribution repo or http://pyyaml.org/wiki/LibYAML
#endif

struct _Config *Config;
struct _Counters *Counters;
struct _Debug *Debug;

struct _Var *Var = NULL;

struct _Bluedot_Skip *Bluedot_Skip;

void Load_YAML_Config( const char *yaml_file )
{

    bool done = false;

    char var_to_value[MAX_VAR_VALUE_SIZE] = { 0 };

    struct stat filecheck;

    unsigned char type = 0;
    unsigned char sub_type = 0;
    unsigned char toggle = 0;

    uint64_t count = 0;
    uint64_t i = 0;

    char *ip_range = NULL;
    char *mask_tmp = NULL;
    uint32_t mask = 0;

    unsigned char ip_bits[MAX_IP_BIT_SIZE] = { 0 };
    unsigned char mask_bits[MAX_IP_BIT_SIZE]= { 0 };

    char *tok = NULL;

    char last_pass[128] = { 0 };

    yaml_parser_t parser;
    yaml_event_t  event;

    /* For lock file path */

    char *lf1 = NULL;
    char *lf2 = NULL;
    char *dir = NULL;
    char *filename = NULL;

    if (stat(yaml_file, &filecheck) != false )
        {
            JAE_Log(ERROR, "[%s, line %d] The configuration file '%s' cannot be found! Abort!", __FILE__, __LINE__, yaml_file);
        }

    FILE *fh = fopen(yaml_file, "r");

    if (!yaml_parser_initialize(&parser))
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to initialize the libyaml parser. Abort!", __FILE__, __LINE__);
        }

    if (fh == NULL)
        {
            JAE_Log(ERROR, "[%s, line %d] Failed to open the configuration file '%s' Abort!", __FILE__, __LINE__, yaml_file);
        }

    /* Set input file */

    yaml_parser_set_input_file(&parser, fh);

    while(!done)
        {

            if (!yaml_parser_parse(&parser, &event))
                {

                    /* Useful YAML vars: parser.context_mark.line+1, parser.context_mark.column+1, parser.problem, parser.problem_mark.line+1, parser.problem_mark.column+1 */

                    JAE_Log(ERROR, "[%s, line %d] libyaml parse error at line %d in '%s'", __FILE__, __LINE__, parser.problem_mark.line+1, yaml_file);

                }

            /* Document start */

            if ( event.type == YAML_DOCUMENT_START_EVENT )
                {

                    if ( Debug->config )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] CONFIG: YAML_DOCUMENT_START_EVENT", __FILE__, __LINE__);
                        }

                    yaml_version_directive_t *ver = event.data.document_start.version_directive;

                    if ( ver == NULL )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Invalid configuration file. Configuration must start with \"%%YAML 1.1\"", __FILE__, __LINE__);
                        }

                    int major = ver->major;
                    int minor = ver->minor;

                    if (! (major == YAML_VERSION_MAJOR && minor == YAML_VERSION_MINOR) )
                        {
                            JAE_Log(ERROR, "[%s, line %d] Configuration has a invalid YAML version.  Must be 1.1 or above", __FILE__, __LINE__);
                        }

                } /* Document start */

            /* Document end! */

            else if ( event.type == YAML_STREAM_END_EVENT )
                {

                    done = true;

                    if ( Debug->config )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] CONFIG: YAML_STREAM_END_EVENT", __FILE__, __LINE__);
                        }
                }

            else if ( event.type == YAML_MAPPING_START_EVENT )
                {

                    toggle = 1;

                    if ( Debug->config )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] CONFIG: YAML_MAPPING_START_EVENT", __FILE__, __LINE__);
                        }
                }

            else if ( event.type == YAML_MAPPING_END_EVENT )
                {

                    toggle = 0;
                    sub_type = 0;

                    if ( Debug->config )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] CONFIG: YAML_MAPPING_END_EVENT", __FILE__, __LINE__);
                        }
                }


            else if ( event.type == YAML_SCALAR_EVENT )
                {

                    char *value = (char *)event.data.scalar.value;

                    Var_To_Value(value, var_to_value, sizeof(var_to_value));


                    if ( Debug->config )
                        {
                            JAE_Log(DEBUG, "[%s, line %d] CONFIG: YAML_SCALAR_EVENT - Value: \"%s\"", __FILE__, __LINE__, value);
                        }

                    /* Load variables! */

                    if ( type == YAML_TYPE_VAR )
                        {

                            if ( toggle == 1 )
                                {

                                    Var = (_Var *) realloc(Var, (Counters->var+1) * sizeof(_Var));

                                    if ( Var == NULL )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Var. Abort!", __FILE__, __LINE__);
                                        }

                                    memset(&Var[Counters->var], 0, sizeof(struct _Var));

                                    snprintf(Var[Counters->var].key, sizeof(Var[Counters->var].key), "$%s", value);
                                    Var[Counters->var].key[sizeof(Var[Counters->var].key)-1] = '\0';
                                    toggle = 0;

                                }
                            else
                                {

                                    if (strcmp(Var[Counters->var].key, ""))
                                        {

                                            /* If "file:/" is found, we load values from a file */

                                            if (JAE_strstr(value, "file:/"))
                                                {

                                                    strtok_r(value, ":", &tok);

                                                    char *filename = NULL;
                                                    char tmpbuf[MAX_CONFIG_LINE] = { 0 };
                                                    FILE *varfile;
                                                    bool check = 0;

                                                    filename = strtok_r(NULL, ":", &tok);

                                                    if ( filename == NULL )
                                                        {
                                                            JAE_Log(ERROR, "[%s, line %d] Attempted to load variable value via file:/ but no file found. Abort!",  __FILE__, __LINE__);
                                                        }

                                                    if ((varfile = fopen(filename, "r")) == NULL)
                                                        {
                                                            JAE_Log(ERROR, "[%s, line %d] Cannot open var file:%s\n", __FILE__,  __LINE__, filename);
                                                        }


                                                    while(fgets(tmpbuf, sizeof(tmpbuf), varfile) != NULL)
                                                        {


                                                            /* Stuff to skip */

                                                            if (tmpbuf[0] == '#') continue;
                                                            if (tmpbuf[0] == ';') continue;
                                                            if (tmpbuf[0] == 10 ) continue;
                                                            if (tmpbuf[0] == 32 ) continue;

                                                            /* Simple check to see if this is the first entry or not.  This is to keep our "," on mark */

                                                            Remove_Return(tmpbuf);

                                                            if ( Debug->config )
                                                                {

                                                                    JAE_Log(DEBUG, "[%s, line %d] CONFIG: Variable from file \"%s\" var \"%s\" loaded: \"%s\"", __FILE__, __LINE__, filename, Var[Counters->var].value, tmpbuf);
                                                                }

                                                            if ( check == 0 )
                                                                {

                                                                    check = 1;

                                                                }

                                                            /* Append to the var */

                                                            strlcat(Var[Counters->var].value, tmpbuf, sizeof(Var[Counters->var].value));


                                                            Var[Counters->var].value[strlen(Var[Counters->var].value)] = ',';
                                                            Var[Counters->var].value[strlen(Var[Counters->var].value) + 1] = '\0';

                                                        }

                                                    Var[Counters->var].value[strlen(Var[Counters->var].value) - 1] = '\0';


                                                    fclose(varfile);

                                                    if ( Debug->config )
                                                        {

                                                            JAE_Log(DEBUG, "[%s, line %d] CONFIG: Final load from file for \"%s\" value \"%s\"", __FILE__, __LINE__, Var[Counters->var].key, Var[Counters->var].value);

                                                        }

                                                    __atomic_add_fetch(&Counters->var, 1, __ATOMIC_SEQ_CST);

                                                    toggle = 1;

                                                }
                                            else
                                                {

                                                    /* If "file:/" is not found, we load like a normal variable */

                                                    strlcpy(Var[Counters->var].value, value, sizeof(Var[Counters->var].value));

                                                    if ( Debug->config )
                                                        {

                                                            JAE_Log(DEBUG, "[%s, line %d] CONFIG: Variable: \"%s == %s\"", __FILE__, __LINE__, Var[Counters->var].key, Var[Counters->var].value);
                                                        }

                                                    __atomic_add_fetch(&Counters->var, 1, __ATOMIC_SEQ_CST);

                                                    toggle = 1;

                                                }
                                        }

                                }

                        }  /* if type == YAML_TYPE_VAR */

                    else if ( type == YAML_TYPE_CORE )
                        {

                            /*
                                                        if ( !strcmp(last_pass, "ip" ) )
                                                            {

                                                                if (  Validate_IP(var_to_value) == true )
                                                                    {
                                                                        strlcpy(Config->ip, var_to_value, sizeof(Config->ip));
                                                                    }
                                                                else
                                                                    {
                                                                        JAE_Log(ERROR, "[%s, line %d] The configuration 'ip' is set to %s which is not a valid IPv4/IPv6 address. Abort", __FILE__, __LINE__, var_to_value);
                                                                    }
                                                            }

                                                        else if ( !strcmp(last_pass, "port" ) )
                                                            {

                                                                Config->port = atoi(var_to_value);

                                                                if (  Config->port == 0 )
                                                                    {
                                                                        JAE_Log(ERROR, "[%s, line %d] The configuration 'port' is set to %s which is not a valid port. Abort", __FILE__, __LINE__, var_to_value);
                                                                    }

                                                            }

                                                        else if ( !strcmp(last_pass, "proto" ) )
                                                            {

                                                                if ( !strcasecmp(var_to_value, "udp") )
                                                                    {
                                                                        Config->proto[0] = 'U';
                                                                        Config->proto[1] = 'D';
                                                                        Config->proto[2] = 'P';
                                                                        Config->proto[3] = '\0';

                                                                        Config->proto_int = 17;
                                                                    }

                                                                else if ( !strcasecmp(var_to_value, "tcp") )
                                                                    {
                                                                        Config->proto[0] = 'T';
                                                                        Config->proto[1] = 'C';
                                                                        Config->proto[2] = 'P';
                                                                        Config->proto[3] = '\0';

                                                                        Config->proto_int = 6;
                                                                    }

                                                                else if ( !strcasecmp(var_to_value, "icmp") )
                                                                    {
                                                                        Config->proto[0] = 'I';
                                                                        Config->proto[1] = 'C';
                                                                        Config->proto[2] = 'M';
                                                                        Config->proto[3] = 'P';
                                                                        Config->proto[4] = '\0';

                                                                        Config->proto_int = 1;
                                                                    }


                                                                if ( Config->proto_int == 0 )
                                                                    {
                                                                        JAE_Log(ERROR, "[%s, line %d] The configuration 'proto' is set to %s which is not a valid. Valid options are UDP, TCP or ICMP. Abort", __FILE__, __LINE__, var_to_value);
                                                                    }

                                                            }
                            			*/

                            if ( !strcmp(last_pass, "max-threads" ) )
                                {

                                    Config->max_threads = atoi(var_to_value);

                                    if ( Config->max_threads == 0 )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] The configuration 'max_threads' is set to %s which is invalid. Abort", __FILE__, __LINE__, var_to_value);
                                        }

                                }

                            else if ( !strcmp(last_pass, "batch-size" ) )
                                {

                                    Config->batch_size = atoi(var_to_value);

                                    if ( Config->batch_size == 0 )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] The configuration 'batch_size' is set to %s which is invalid. Abort", __FILE__, __LINE__, var_to_value);
                                        }

                                }

                            else if ( !strcmp(last_pass, "classifications" ) )
                                {
                                    strlcpy(Config->classifications_file, var_to_value, sizeof(Config->classifications_file));
                                    Remove_Return(Config->classifications_file);
                                    Load_Classifications();

                                }

                            else if ( !strcmp(last_pass, "reference" ) )
                                {
                                    strlcpy(Config->reference_file, var_to_value, sizeof(Config->reference_file));
                                    Remove_Return(Config->reference_file);
                                }

                            else if ( !strcmp(last_pass, "normalize" ) )
                                {
                                    strlcpy(Config->normalize_file, var_to_value, sizeof(Config->normalize_file));
                                    Remove_Return(Config->normalize_file);
                                }


                            else if ( !strcmp(last_pass, "lockfile" ) )
                                {
                                    strlcpy(Config->lock_file, var_to_value, sizeof(Config->lock_file));
                                    Remove_Return(Config->lock_file);

                                    lf1 = strdup(Config->lock_file);
                                    lf2 = strdup(Config->lock_file);

                                    dir = dirname(lf1);

                                    if ( dir == NULL )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] Directory for lock file appears '%s' to be incorrect. Abort",  __FILE__, __LINE__, Config->lock_file);
                                        }

                                    strlcpy(Config->lock_file_path, dir, sizeof(Config->lock_file_path));


                                }

                            else if ( !strcmp(last_pass, "runas" ) )
                                {
                                    strlcpy(Config->runas, var_to_value, sizeof(Config->runas));
                                    Remove_Return(Config->runas);
                                }

                            else if ( !strcmp(last_pass, "sensor-name" ) )
                                {
                                    strlcpy(Config->sensor_name, var_to_value, MAX_SENSOR_NAME);
                                    Remove_Return(Config->sensor_name);
                                }

                            else if ( !strcmp(last_pass, "cluster-name" ) )
                                {
                                    strlcpy(Config->cluster_name, var_to_value, MAX_CLUSTER_NAME);
                                    Remove_Return(Config->cluster_name);
                                }

                            else if ( !strcmp(last_pass, "parse-ip" ) )
                                {
                                    if ( !strcmp( var_to_value, "pre" ))
                                        {
                                            Config->parse_ip = PARSE_IP_PRE;
                                        }
                                    else
                                        {
                                            Config->parse_ip = PARSE_IP_POST;
                                        }

                                    if ( strcmp( var_to_value, "pre" ) && strcmp( var_to_value, "post" ) )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] config -> 'parse-ip' needs to be 'pre' or 'post' but found '%s'. Abort!",  __FILE__, __LINE__, var_to_value);

                                        }

                                }


                        }

                    else if ( type == YAML_TYPE_PROCESSORS )
                        {

                            if ( !strcmp(value, "bluedot" ) )
                                {
                                    sub_type = YAML_SUBTYPE_BLUEDOT;
                                }
                        }

                    /* Types with sub-types */

                    else if ( type == YAML_TYPE_INPUT )
                        {

                            if ( !strcmp(value, "named-pipe") )
                                {
                                    sub_type = YAML_SUBTYPE_INPUT_PIPE;
                                }

                        }

                    else if ( type == YAML_TYPE_OUTPUT )
                        {

                            if ( !strcmp(value, "file") )
                                {
                                    sub_type = YAML_SUBTYPE_OUTPUT_FILE;
                                }

                        }



                    /********************************************************
                             * Sub types ! - Input
                     ********************************************************/

                    if ( sub_type == YAML_SUBTYPE_INPUT_PIPE && type == YAML_TYPE_INPUT )
                        {

                            if ( !strcmp(last_pass, "enabled" ))
                                {
                                    if (!strcasecmp(var_to_value, "yes") || !strcasecmp(var_to_value, "true") || !strcasecmp(var_to_value, "enabled") )
                                        {
                                            Config->input_named_pipe_flag = true;
                                        }
                                }

                            if ( !strcmp(last_pass, "chown" ))
                                {
                                    if (!strcasecmp(var_to_value, "yes") || !strcasecmp(var_to_value, "true") || !strcasecmp(var_to_value, "enabled") )
                                        {
                                            Config->input_named_pipe_chown = true;
                                        }
                                }


                            else if ( !strcmp(last_pass, "named-pipe" ) && Config->input_named_pipe_flag == true )
                                {
                                    strlcpy(Config->input_named_pipe, var_to_value, sizeof(Config->input_named_pipe));
                                    Remove_Return(Config->input_named_pipe);
                                }



#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)

                            else if ( !strcmp(last_pass, "size" ) && Config->input_named_pipe_flag == true )
                                {

                                    Config->input_named_pipe_size = atoi( var_to_value );

                                    if ( Config->input_named_pipe_size == 0 )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] input -> named_pipe has a bad pipe size value of %s. Abort!",  __FILE__, __LINE__, var_to_value);
                                        }

                                    if ( Config->input_named_pipe_size != 65536 &&
                                            Config->input_named_pipe_size != 131072 &&
                                            Config->input_named_pipe_size != 262144 &&
                                            Config->input_named_pipe_size != 524288 &&
                                            Config->input_named_pipe_size != 1048576 )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] input -> named_pipe has a bad pipe size value of %s. The size can only be 65536, 131072, 262144, 524288, or 1048576. Abort!",  __FILE__, __LINE__, var_to_value);
                                        }

                                }

#endif

                        }

                    /********************************************************
                     * Sub types ! - Input
                     ********************************************************/

                    if ( sub_type == YAML_SUBTYPE_OUTPUT_FILE && type == YAML_TYPE_OUTPUT )
                        {

                            if ( !strcmp(last_pass, "enabled" ))
                                {
                                    if (!strcasecmp(var_to_value, "yes") || !strcasecmp(var_to_value, "true") || !strcasecmp(var_to_value, "enabled") )
                                        {
                                            Config->output_file_flag = true;
                                        }
                                }

                            if ( !strcmp(last_pass, "output-file" ))
                                {
                                    strlcpy(Config->output_file, var_to_value, MAX_PATH);
                                }

                            if ( !strcmp(last_pass, "flatten-json" ))
                                {
                                    if (!strcasecmp(var_to_value, "yes") || !strcasecmp(var_to_value, "true") || !strcasecmp(var_to_value, "enabled") )
                                        {
                                            Config->output_file_flatten_json = true;
                                        }
                                }

                            if ( !strcmp(last_pass, "append-alert-data" ))
                                {
                                    if (!strcasecmp(var_to_value, "yes") || !strcasecmp(var_to_value, "true") || !strcasecmp(var_to_value, "enabled") )
                                        {
                                            Config->output_file_append_alert_data = true;
                                        }
                                }

                        }

                    /* Sub processor type ! - Bluedot */

                    if ( sub_type == YAML_SUBTYPE_BLUEDOT && type == YAML_TYPE_PROCESSORS )
                        {

                            if ( !strcmp(last_pass, "enabled" ))
                                {
                                    if (!strcasecmp(var_to_value, "yes") || !strcasecmp(var_to_value, "true") || !strcasecmp(var_to_value, "enabled") )
                                        {
                                            Config->processor_bluedot_flag = true;
                                        }
                                }

                            if ( !strcmp(last_pass, "dns-ttl" ) && Config->processor_bluedot_flag == true )
                                {

                                    Config->processor_bluedot_dns_ttl = atoi( var_to_value );

                                    if ( Config->processor_bluedot_dns_ttl == 0 )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] The 'bluedot' configuration 'dns-ttl' is set to \"%s\" which is invalid. Abort", __FILE__, __LINE__, var_to_value);
                                        }
                                }

                            if ( !strcmp(last_pass, "ip-queue" ) && Config->processor_bluedot_flag == true )
                                {

                                    Config->processor_bluedot_ip_queue = atoi( var_to_value );

                                    if ( Config->processor_bluedot_ip_queue == 0 )
                                        {
                                            JAE_Log(ERROR, "[%s, line %d] The 'bluedot' configuration 'ip_queue' is set to \"%s\" which is invalid. Abort", __FILE__, __LINE__, var_to_value);
                                        }

                                }

                            if ( !strcmp(last_pass, "host" ) && Config->processor_bluedot_flag == true )
                                {
                                    strlcpy(Config->processor_bluedot_host, var_to_value, sizeof(Config->processor_bluedot_host));
                                }

                            if ( !strcmp(last_pass, "uri" ) && Config->processor_bluedot_flag == true )
                                {
                                    strlcpy(Config->processor_bluedot_uri, var_to_value, sizeof(Config->processor_bluedot_uri));
                                }

                            if ( !strcmp(last_pass, "device-id" ) && Config->processor_bluedot_flag == true )
                                {
                                    strlcpy(Config->processor_bluedot_device_id, var_to_value, sizeof(Config->processor_bluedot_device_id));
                                }




                            if ( !strcmp(last_pass, "skip-networks" ) && Config->processor_bluedot_flag == true )
                                {


                                    /* Load from file */

                                    struct _Simple_Array *Simple_Array;

                                    if ( var_to_value[0] == 'f' && var_to_value[1] == 'i' && var_to_value[2] == 'l' &&
                                            var_to_value[3] == 'e' && var_to_value[4] == ':' && var_to_value[5] == '/' )
                                        {

                                            char tmp_file[255] = { 0 };

                                            /* Grab only the file path + name */

                                            strlcpy(tmp_file, var_to_value+6, sizeof(tmp_file));

                                            Simple_Array = Load_Simple_File ( (const char *)tmp_file);

                                        }
                                    else
                                        {

                                            Simple_Array = Comma_Delimited_Simple ( (char *)var_to_value);
                                        }

//                                    count = 0;

                                    while ( Simple_Array[Counters->processor_bluedot_skip].item[0] != '\0' )
                                        {

                                            ip_range = strtok_r( Simple_Array[Counters->processor_bluedot_skip].item, "/", &tok );

                                            if ( ip_range == NULL )
                                                {
                                                    JAE_Log(ERROR, "[%s, line %d] processor 'bluedot' has a invalid 'skip_networks' entry of '%s'. Abort!", __FILE__, __LINE__, var_to_value);
                                                }

                                            if (!IP_2_Bit(ip_range, ip_bits))
                                                {
                                                    JAE_Log(ERROR, "[%s, line %d] processor 'bluedot' has a invalid 'skip_networks' entry of '%s'. Abort!", __FILE__, __LINE__, var_to_value);
                                                }

                                            mask_tmp = strtok_r(NULL, "/", &tok);

                                            /* Default to /32 if NULL */

                                            if ( mask_tmp == NULL )
                                                {
                                                    mask = 32;
                                                }

                                            Bluedot_Skip = (_Bluedot_Skip *) realloc(Bluedot_Skip, (Counters->processor_bluedot_skip+1) * sizeof(_Bluedot_Skip));

                                            if ( Bluedot_Skip == NULL )
                                                {
                                                    JAE_Log(ERROR, "[%s, line %d] processor 'bluedot' failed to allocate memory for _Bluedot_Skip. Abort!", __FILE__, __LINE__);
                                                }

                                            memset(&Bluedot_Skip[Counters->processor_bluedot_skip], 0, sizeof(_Bluedot_Skip));

                                            mask = atoi(mask_tmp);

                                            if ( mask == 0 || !Mask_2_Bit(mask, mask_bits) )
                                                {
                                                    JAE_Log(ERROR, "[%s, line %d] processor 'bluedot' - Invalid mask for 'skip_networks'. Abort!", __FILE__, __LINE__);
                                                }

                                            memcpy(Bluedot_Skip[Counters->processor_bluedot_skip].range.ipbits, ip_bits, MAX_IP_BIT_SIZE);
                                            memcpy(Bluedot_Skip[Counters->processor_bluedot_skip].range.maskbits, mask_bits, MAX_IP_BIT_SIZE);

                                            __atomic_add_fetch(&Counters->processor_bluedot_skip, 1, __ATOMIC_SEQ_CST);

                                        }

					free(Simple_Array);
                                }

                        }


                    else if ( type == YAML_TYPE_RULES )
                        {
                            Load_Ruleset( var_to_value );
                        }

                    strlcpy(last_pass, var_to_value, sizeof(last_pass));


                    /**** Tag types *************************************************/

                    /**************/
                    /**** vars ****/
                    /**************/

                    if (!strcmp(value, "vars"))
                        {

                            if ( Debug->config )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] CONFIG: **** Found variables ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_VAR;
                            toggle = 0;

                        } /* tag: var */

                    else if (!strcmp(value, "configuration"))
                        {

                            if ( Debug->config )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] CONFIG: **** Found \"configuration\" ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_CORE;
                            toggle = 0;

                        } /* tag: var */

                    else if (!strcmp(value, "input"))
                        {

                            if ( Debug->config )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] CONFIG: **** Found \"input\" ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_INPUT;
                            toggle = 0;

                        } /* tag: input */

                    else if (!strcmp(value, "output"))
                        {

                            if ( Debug->config )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] CONFIG: **** Found \"output\" ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_OUTPUT;
                            toggle = 0;

                        } /* tag: output */

                    else if ( !strcmp(value, "rule-files" ))
                        {

                            if ( Debug->config )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] CONFIG: **** Found \"rule-files\" ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_RULES;
                            toggle = 0;

                        }

                    else if ( !strcmp(value, "processors" ))
                        {

                            if ( Debug->config )
                                {
                                    JAE_Log(DEBUG, "[%s, line %d] CONFIG: **** Found \"processors\" ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_PROCESSORS;
                            toggle = 0;

                        }


                } /* End of "while */

        }

    yaml_parser_delete(&parser);
    fclose(fh);

}


struct _Simple_Array *Comma_Delimited_Simple ( char *string )
{

    char *ptr1 = NULL;
    char *ptr2 = NULL;

    uint64_t count = 0;

    struct _Simple_Array *Simple_Array = NULL;


    Remove_Spaces(string);

    ptr1 = strtok_r(string, ",", &ptr2);

    while ( ptr1 != NULL )
        {

            Simple_Array = (_Simple_Array *) realloc(Simple_Array, (count+1) * sizeof(_Simple_Array));

            if ( Simple_Array == NULL )
                {
                    Remove_Lock_File();
                    JAE_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Simple_Array.  Abort!", __FILE__, __LINE__);
                }

            memset(&Simple_Array[count], 0, sizeof(struct _Simple_Array));

            strlcpy(Simple_Array[count].item, ptr1, MAX_ITEM_SIZE);

            count++;
            ptr1 = strtok_r(NULL, ",", &ptr2);

        }


    return( Simple_Array );

}


