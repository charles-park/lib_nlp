//------------------------------------------------------------------------------
/**
 * @file lib_nlp.h
 * @author charles-park (charles.park@hardkernel.com)
 * @brief Zebra netwrok label printer control library.
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
#ifndef __LIB_NLP_H__
#define __LIB_NLP_H__

//------------------------------------------------------------------------------
#define NLP_LIST_MAX    10

struct nlp_info {
    char    conn;       // 1 = connect, 0 = disconnect
    int     port;       // 9100 or 8888 (NLP port)
    char    ip [20];    // aaa.bbb.ccc.ddd
    char    mac[20];    // aabbccddeeff
    void    *list;      // nlp list
};

//------------------------------------------------------------------------------
// default net device info
#define	NET_DEFAULT_NAME    "eth0"
#define NET_IP_BASE         "192.168."

// Direct Net연결하여 프린트 되어지는 포트는 TCP : 9100 (Model ZD230D)
#define NLP_PORT_DIRECT 9100

// ODROID-C4를 사용하여 프린트되어지는 포트는 TCP : 8888
#define NLP_PORT_SERVER 8888

// NPL print msg type
#define MSG_TYPE_MAC    0
#define MSG_TYPE_ERR    1

// channel info
#define CH_NONE         0
#define CH_LEFT         0
#define CL_RIGHT        1

// NLP print width/height(char)
#define	NPL_PRINT_WIDTH     18
#define	NPL_PRINT_HEIGHT    3

//------------------------------------------------------------------------------
//	function prototype
//------------------------------------------------------------------------------
extern int     get_iface_info  (struct nlp_info *info, const char *if_name);

extern int     nlp_status      (const char *nlp_ip);
extern void    nlp_scan_list   (const struct nlp_info *nlp_info);
extern int     nlp_printf      (const struct nlp_info *nlp_info, const char mtype, const char *msg, const char ch);
extern int     nlp_init        (struct nlp_info *nlp_info, const char *if_name);
extern void    nlp_deinit      (struct nlp_info *nlp_info);

//------------------------------------------------------------------------------
#endif  // #ifndef __LIB_NLP_H__
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
