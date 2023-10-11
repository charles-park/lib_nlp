//------------------------------------------------------------------------------
/**
 * @file lib_main.c
 * @author charles-park (charles.park@hardkernel.com)
 * @brief Zebra netwrok label printer control application.
 * @version 0.2
 * @date 2023-09-19
 *
 * @package apt install cups cups-bsd
 *
 * @copyright Copyright (c) 2022
 *
 */
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/fb.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include "lib_nlp.h"

//------------------------------------------------------------------------------
#if defined(__LIB_NLP_APP__)

//------------------------------------------------------------------------------
const char *OPT_MSG_STR    = NULL;
const char *OPT_NLP_IP     = NULL;
const char *OPT_NLP_MAC    = NULL;
const char *OPT_NLP_PORT   = NULL;
const char *OPT_IFACE_NAME = NULL;

static char OPT_CHANNEL    = 0;
static char OPT_NLP_LIST   = 0;
static char OPT_MSG_ERR    = 0;
static char OPT_MAC_PRINT  = 0;

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
static void print_usage(const char *prog)
{
    puts("");
    printf("Usage: %s [-lipIMPctm]\n", prog);
    puts("");

    puts("  -l --list_nlp   scan & network label printer list.\n"
         "  -i --iface_name iface name\n"
         "  -p --mac_print  print mac address (default iface name = eth0).\n"
         "  -I --nlp_ip     Fixed Network printer ip.\n"
         "  -M --nlp_mac    Fixed Network printer mac.\n"
         "  -P --nlp_port   Fixed Network printer port.\n"
         "  -c --channel    Message channel (left or right, default = left)\n"
         "  -t --msg_type   message type (mac or error, default = mac)\n"
         "  -m --msg        print message.\n"
         "                  type == mac, msg is 001e06??????\n"
         "                  type == error, msg is usb,???,...\n"
         "\n"
         "   e.g) lib_nlp -l\n"
         "        lib_nlp -c left -t error -m usb,sata,hdd\n"
         "        lib_nlp -c right -t mac -m 001e06234567\n"
    );
    exit(1);
}

//-------------------e-----------------------------------------------------------
static void tolowerstr (char *p)
{
    int i, c = strlen(p);

    for (i = 0; i < c; i++, p++)
        *p = tolower(*p);
}

//------------------------------------------------------------------------------
static void toupperstr (char *p)
{
    int i, c = strlen(p);

    for (i = 0; i < c; i++, p++)
        *p = toupper(*p);
}

//------------------------------------------------------------------------------
static void parse_opts (int argc, char *argv[])
{
    while (1) {
        static const struct option lopts[] = {
            { "list_nlp",   0, 0, 'l' },
            { "iface_name", 1, 0, 'i' },
            { "mac_print",  0, 0, 'p' },
            { "nlp_ip",     1, 0, 'I' },
            { "nlp_mac",    1, 0, 'M' },
            { "nlp_port",   1, 0, 'P' },
            { "channle",    1, 0, 'c' },
            { "msg_type",   1, 0, 't' },
            { "msg_str",    1, 0, 'm' },
            { NULL, 0, 0, 0 },
        };
        int c;

        c = getopt_long(argc, argv, "lpi:I:M:P:c:t:m:z", lopts, NULL);

        if (c == -1)
            break;

        switch (c) {
        case 'l':
            OPT_NLP_LIST = 1;
            break;
        case 'p':
            OPT_MAC_PRINT = 1;
            break;
        case 'i':
            tolowerstr(optarg);
            OPT_IFACE_NAME = optarg;
            break;
        case 'I':
            OPT_NLP_IP = optarg;
            break;
        case 'M':
            toupperstr(optarg);
            OPT_NLP_MAC = optarg;
            break;
        case 'P':
            OPT_NLP_PORT = optarg;
            break;
        case 'c':
            tolowerstr (optarg);
            if (!strncmp("right", optarg, strlen("right")))
                OPT_CHANNEL = 1;
            else
                OPT_CHANNEL = 0;
            break;
        case 't':
            tolowerstr (optarg);
            if (!strncmp("error", optarg, strlen("error")))
                OPT_MSG_ERR = 1;
            else
                OPT_MSG_ERR = 0;
            break;
        case 'm':
            OPT_MSG_STR = optarg;
            break;
        default:
            print_usage(argv[0]);
            break;
        }
    }
}

//------------------------------------------------------------------------------
int main (int argc, char **argv)
{
    struct nlp_info nlp_info;

    parse_opts (argc, argv);

    memset  (&nlp_info, 0, sizeof(struct nlp_info));

    if (OPT_MAC_PRINT) {
        struct nlp_info iface_info;
        if (get_iface_info(&iface_info, OPT_IFACE_NAME)) {
            if (nlp_init (&nlp_info, OPT_IFACE_NAME)) {

                printf ("Send to Net Printer(%s:%d)!! (string : %s), send = %s\n",
                        nlp_info.ip, nlp_info.port,
                        iface_info.mac,
                        nlp_printf (&nlp_info, MSG_TYPE_MAC, iface_info.mac, CH_NONE) ? "true" : "fail");
            }
        }
        return 0;
    }

    if (OPT_NLP_IP != NULL)
        memcpy (&nlp_info.ip, OPT_NLP_IP, strlen(OPT_NLP_IP));
    if (OPT_NLP_MAC != NULL)
        memcpy (&nlp_info.mac, OPT_NLP_MAC, strlen(OPT_NLP_MAC));
    if (OPT_NLP_PORT != NULL)
        nlp_info.port = atoi(OPT_NLP_PORT);

    nlp_init (&nlp_info, OPT_IFACE_NAME);
    if (OPT_NLP_LIST)
        nlp_scan_list (&nlp_info);

    if (OPT_MSG_STR != NULL) {
        if (nlp_info.conn)
            nlp_printf (&nlp_info, OPT_MSG_ERR, OPT_MSG_STR, OPT_CHANNEL);
    }
    return 0;
}

//------------------------------------------------------------------------------
#endif  // #if defined(__LIB_NLP_APP__)
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
