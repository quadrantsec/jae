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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <pthread.h>


#include "jae.h"
#include "jae-defs.h"
#include "jae-config.h"

#include "util-tcpip.h"

bool Is_In_Range ( unsigned char *ip, unsigned char *tests, int count )
{

    int i,j,k;
    bool inrange = false;

    for (i=0; i<count*MAX_IP_BIT_SIZE*2; i+=MAX_IP_BIT_SIZE*2)
        {
            inrange = true;

            /* We can stop if the mask is 0.  We only handle wellformed masks. */

            for(j=0,k=16; j<16 && tests[i+k] != 0x00; j++,k++)
                {
                    if((tests[i+j] & tests[i+k]) != (ip[j] & tests[i+k]))
                        {
                            inrange = false;
                            break;
                        }
                }
            if (inrange)
                {
                    break;
                }
        }
    return inrange;
}

/****************************************************************************/
/* Is_Not_Routable                                                          */
/*                                                                          */
/* Checks to see if an ip address is routable or not                        */
/****************************************************************************/

bool Is_Not_Routable ( unsigned char *ip )
{

    /* Start of subnet followd by mask */

    static unsigned char tests[][32] =
    {

        // IPv6 Multicast - ff00::/8
        {
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv6 Link Local fe80::/10
        {
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv6 RFC4193 - fc00::/7
        {
            0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv6  LocalHost - ::1/128
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        },
        // IPv4 RFC1918 - 10.0.0.0/8
        {
            0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped RFC1918 - ::ffff:10.0.0.0/104
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xA0, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00
        },
        // IPv4 RFC1918 - 192.168.0.0/16
        {
            0xC0, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped RFC1918 - ::ffff:192.168.0.0/112
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xC0, 0xA8, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00
        },

        // IPv4 localhost - 127.0.0.0/8
        {
            0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped localhost - ::ffff:127.0.0.0/104
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00
        },
        // IPv4  Mulitcast - 224.0.0.0/4
        {
            0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped  Mulitcast - ::ffff:224.0.0.0/100
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00
        },
        // IPv4  Broadcast - 255.255.255.255/32
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped  Broadcast - ::ffff:255.255.255.255/128
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        },
        // IPv4 RFC1918 - 172.16.0.0/12
        {
            0xAC, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped RFC1918 - ::ffff:172.16.0.0/108
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xAC, 0x10, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6C, 0x00, 0x00
        },
        // IPv4 RFC1918 - 172.16.0.0/12
        {
            0xAC, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        // IPv4-mapped RFC1918 - ::ffff:172.16.0.0/108
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xAC, 0x10, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6C, 0x00, 0x00
        },
        // 169.254.0.0/16 - APIPA - Automatic Private IP Addressing
        {
            0xA9, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        }

    };

    return Is_In_Range(ip, (unsigned char *)tests, sizeof(tests)/(sizeof(char[32])));
}


bool IP_2_Bit( char *ipaddr, unsigned char *out )
{

    bool ret = false;
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;

    /* Use getaddrinfo so we can get ipv4 or 6 */

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE|AI_NUMERICHOST;

    if ( ipaddr == NULL || ipaddr[0] == '\0' )
        {
            return false;
        }

    ret = getaddrinfo(ipaddr, NULL, &hints, &result) == 0;


    if (!ret)
        {
//            JAE_Log(WARN, "[%lu] Warning: Got a getaddrinfo() error for \"%s\" but continuing...", pthread_self(), ipaddr);
        }
    else
        {

            switch (((struct sockaddr_storage *)result->ai_addr)->ss_family)
                {
                case AF_INET:

                    ret = true;
                    if (out != NULL)
                        {
                            memcpy(out, &((struct sockaddr_in *)result->ai_addr)->sin_addr, sizeof(((struct sockaddr_in *)0)->sin_addr));
                        }
                    break;

                case AF_INET6:

                    ret = true;
                    if (out != NULL)
                        {
                            memcpy(out, &((struct sockaddr_in6 *)result->ai_addr)->sin6_addr, sizeof(((struct sockaddr_in6 *)0)->sin6_addr));
                        }
                    break;

                default:
                    JAE_Log(WARN, "[%lu] Warning: Got a getaddrinfo() received a non IPv4/IPv6 address for \"%s\" but continuing...", pthread_self(), ipaddr);
                }
        }

    if (result != NULL)
        {
            freeaddrinfo(result);
        }

    return ret;
}

/********************************************************************
 * DNS lookup of hostnames.  Wired for IPv4 and IPv6.  Code largely
 * based on Beej's showip.c
 ********************************************************************/

bool DNS_Lookup( char *host, char *str, size_t size )
{

    char ipstr[INET6_ADDRSTRLEN] = { 0 };

    struct addrinfo hints = {0}, *res = NULL;
    int status;
    void *addr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     /* AF_INET or AF_INET6 to force version */
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0)
        {

            JAE_Log(WARN, "%s: %s", gai_strerror(status), host);
            return(false);

        }

    if (res->ai_family == AF_INET)   /* IPv4 */
        {

            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            addr = &(ipv4->sin_addr);

        }
    else     /* IPv6 */
        {

            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
            addr = &(ipv6->sin6_addr);

        }

    inet_ntop(res->ai_family, addr, ipstr, sizeof ipstr);
    freeaddrinfo(res);

    snprintf(str, size, "%s", ipstr);
    return(true);
}

bool Mask_2_Bit( int mask, unsigned char *out )
{
    int i;
    bool ret = false;

    if (mask < 1 || mask > 128)
        {
            return false;
        }

    ret = true;

    for (i=0; i<mask; i+=8)
        {
            out[i/8] = i+8 <= mask ? 0xff : ~((1 << (8 - mask%8)) - 1);
        }
    return ret;

}


