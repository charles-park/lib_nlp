//------------------------------------------------------------------------------
/**
 * @file lib_nlp.c
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
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/fb.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include "lib_nlp.h"

//------------------------------------------------------------------------------
// Debug msg
//------------------------------------------------------------------------------
#if defined (__LIB_SINGLE_APP__)
    #define dbg_msg(fmt, args...)   printf(fmt, ##args)
#else
    #define dbg_msg(fmt, args...)
#endif

//------------------------------------------------------------------------------
// function prototype
//------------------------------------------------------------------------------
static void tolowerstr      (char *p);
static void toupperstr      (char *p);
static int  read_with_timeout (int fd, char *buf, int buf_size, int timeout_ms);

int  get_iface_info         (struct nlp_info *info, const char *if_name);

static void nlp_disconnect  (int nlp_fp);
static int  nlp_connect     (const struct nlp_info *nlp_info);
static int  nlp_version     (const struct nlp_info *nlp_info, char *get_ver);
static int  nlp_find        (const int ip_base, const int nlp_port, struct nlp_info *nlp_list, int info_cnt);
static int  nlp_scan        (struct nlp_info *nlp_list, const char *if_name);
static void convert_to_zpl  (char *sbuf, char mtype, char *msg, char ch);
static int  nlp_write       (const struct nlp_info *nlp_info, char mtype, char *msg, char ch);

int     nlp_status      (const char *nlp_ip);
void    nlp_scan_list   (const struct nlp_info *nlp_info);
int     nlp_printf      (const struct nlp_info *nlp_info, const char mtype, const char *msg, const char ch);
int     nlp_init        (struct nlp_info *nlp_info, const char *if_name);
void    nlp_deinit      (struct nlp_info *nlp_info);

//------------------------------------------------------------------------------
// 문자열 변경 함수. 입력 포인터는 반드시 메모리가 할당되어진 변수여야 함.
//------------------------------------------------------------------------------
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
// TCP/UDP 데이터 read (timeout가능)
//------------------------------------------------------------------------------
static int read_with_timeout (int fd, char *buf, int buf_size, int timeout_ms)
{
    int rx_len = 0;
    struct timeval timeout;
    fd_set readFds;

    // recive time out config
    // Set 1ms timeout counter
    timeout.tv_sec  = 0;
    timeout.tv_usec = timeout_ms*1000;

    FD_ZERO (&readFds);
    FD_SET  (fd  , &readFds);
    select  (fd+1, &readFds, NULL, NULL, &timeout);

    if(FD_ISSET (fd, &readFds))
    {
        rx_len = read (fd, buf, buf_size);
    }

    return rx_len;
}

//------------------------------------------------------------------------------
// 현재 device(board)의 if_name(ethx)에 할당되어진 ip와 mac address를 얻어온다.
//
// 성공 return 1, 실패 return 0
//------------------------------------------------------------------------------
int get_iface_info (struct nlp_info *info, const char *if_name)
{
    int fd;
    struct ifreq ifr;
    char if_info[20];

    memset (info, 0, sizeof(struct nlp_info));

    /* this entire function is almost copied from ethtool source code */
    /* Open control socket. */
    if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        dbg_msg ("%s : Cannot get control socket\n", __func__);
        return 0;
    }
    strncpy(ifr.ifr_name, (if_name != NULL) ? if_name : NET_DEFAULT_NAME, IFNAMSIZ);
    if (ioctl (fd, SIOCGIFADDR, &ifr) < 0) {
        dbg_msg ("%s : iface name = %s, SIOCGIFADDR ioctl Error!!\n", __func__, if_name);
        close (fd);
        return 0;
    }
    // board(iface) ip
    memset (if_info, 0, sizeof(if_info));
    inet_ntop (AF_INET, ifr.ifr_addr.sa_data+2, if_info, sizeof(struct sockaddr));
    strncpy (info->ip, if_info, strlen(if_info));

    // iface mac
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        memset (if_info, 0, sizeof(if_info));
        memcpy (if_info, ifr.ifr_hwaddr.sa_data, 6);
        sprintf(info->mac, "%02x%02x%02x%02x%02x%02x",
            if_info[0], if_info[1], if_info[2], if_info[3], if_info[4], if_info[5]);
    }
    dbg_msg ("Interface info : iface = %s, ip = %s, mac = %s\n",
        (if_name != NULL) ? if_name : NET_DEFAULT_NAME,
        info->ip, info->mac);

    return 1;
}

//------------------------------------------------------------------------------
// TCP/UDP 연결을 해제한다.
//------------------------------------------------------------------------------
static void nlp_disconnect (int nlp_fp)
{
    if (nlp_fp)
        close(nlp_fp);
}

//------------------------------------------------------------------------------
// 입력된 주소로 연결한다.
//
// 성공 return nlp_fp, 실패 return 0
//------------------------------------------------------------------------------
static int nlp_connect (const struct nlp_info *nlp_info)
{
    int nlp_fp, len;
    struct sockaddr_in s_addr;

    if((nlp_fp = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        dbg_msg ("socket create error : \n");
        return 0;
    }
    len = sizeof(struct sockaddr_in);

    memset (&s_addr, 0, len);

    //소켓에 접속할 주소 지정
    s_addr.sin_family       = AF_INET;
    s_addr.sin_addr.s_addr  = inet_addr(nlp_info->ip);
    s_addr.sin_port         = htons(nlp_info->port);

    // 지정한 주소로 접속
    if(connect (nlp_fp, (struct sockaddr *)&s_addr, len) < 0) {
        dbg_msg ("connect error : %s\n", nlp_info->ip);
        nlp_disconnect (nlp_fp);
        return 0;
    }
    return nlp_fp;
}

//------------------------------------------------------------------------------
// 프로그램 버전을 확인한다. (TCP : 8888의 경우 ODROID Server에 연결되어있기 때문임)
//
// 성공 return 1, 실패 return 0
//------------------------------------------------------------------------------
static int nlp_version (const struct nlp_info *nlp_info, char *get_ver)
{
    char rw_buff[16];
    int nlp_fp = 0, timeout = 1000;

    // ODROID-C4를 사용하여 프린트되어지는 포트는 TCP : 8888
    if (nlp_info->port != NLP_PORT_SERVER)
        return 0;

    if ((nlp_fp = nlp_connect (nlp_info)) > 0) {
        memset (rw_buff, 0, sizeof(rw_buff));
        sprintf(rw_buff, "%s", "version");
        write  (nlp_fp, rw_buff, strlen(rw_buff));

        // wait read ack
        memset (rw_buff, 0, sizeof(rw_buff));
        if (read_with_timeout(nlp_fp, rw_buff, sizeof(rw_buff), timeout)) {
            strncpy(get_ver, rw_buff, strlen(rw_buff));
            dbg_msg ("read version is %s\n", get_ver);
        } else {
            dbg_msg ("read time out %d ms or rbuf is NULL!\n", timeout);
        }
    }
    nlp_disconnect(nlp_fp);

    return nlp_fp ? 1 : 0;
}

//------------------------------------------------------------------------------
//
// ip base에 열려있는 nlp_port를 scan하여 nlp_list변수에 info를 저장한다.
//
// 성공 return info_cnt, 실패 return 0
//
//------------------------------------------------------------------------------
static int nlp_find (const int ip_base, const int nlp_port, struct nlp_info *nlp_list, int info_cnt)
{
    FILE *fp;
    char cmd[80], rbuff[4096], *ip_tok;

    memset (cmd, 0, sizeof(cmd));
    sprintf(cmd, "nmap 192.168.%d.* -p T:%4d --open", ip_base, nlp_port);

    if (NULL == (fp = popen(cmd, "r")))
    {
        dbg_msg ("popen() error!\n");
        return 0;
    }

    // start info offset
    nlp_list = nlp_list + info_cnt;

    while (fgets(rbuff, 4096, fp)) {
        ip_tok = strstr(rbuff, NET_IP_BASE);
        if (ip_tok != NULL) {
            if (nlp_status (ip_tok)) {
                memset (nlp_list, 0, sizeof(struct nlp_info));
                strncpy(nlp_list->ip, ip_tok, strlen(ip_tok)-1);
                nlp_list->conn = 0;
                nlp_list->port = nlp_port;
                while (fgets(rbuff, 4096, fp)) {
                    ip_tok = strstr(rbuff, "MAC Address:");
                    if (ip_tok != NULL) {

                        // aa:bb:cc:dd:ee:ff -> aabbccddeeff
                        sprintf(nlp_list->mac,"%c%c%c%c%c%c%c%c%c%c%c%c",
                            *(ip_tok + 13), *(ip_tok + 14), *(ip_tok + 16), *(ip_tok + 17),
                            *(ip_tok + 19), *(ip_tok + 20), *(ip_tok + 22), *(ip_tok + 23),
                            *(ip_tok + 25), *(ip_tok + 26), *(ip_tok + 28), *(ip_tok + 29));

                        nlp_list++; info_cnt++;
                        break;
                    }
                }
            }
        }
    }
    pclose(fp);
    return info_cnt;
}

//------------------------------------------------------------------------------
// 현재 board ip를 기준으로 같은 Network상에 있는 NLP를 검색한다.
//
// 9100포트와 8888포트를 순차적으로 검색하여 global NlpList 변수에 저장.
//
// 성공 return NLP 찾은개수, 실패 return 0
//------------------------------------------------------------------------------
static int nlp_scan (struct nlp_info *nlp_list, const char *if_name)
{
    char *ip_tok, ip_base[20];
    int ip, info_cnt = 0;
    struct nlp_info iface_info;

    /* iface name에 따른 ip, mac info를 얻어온다. */
    get_iface_info (&iface_info, if_name);

    memset (ip_base, 0, sizeof(ip_base));
    memcpy (ip_base, iface_info.ip, strlen(iface_info.ip));
    /*
        얻어온 보드 ip aaa.bbb.ccc.ddd에서 ccc위치의 값을 가져옴.
        해당 네트워크상에 있는 프린터를 검색하기 위함.
    */
    ip_tok = strtok(ip_base, ".");
    ip_tok = strtok(NULL,    ".");
    ip_tok = strtok(NULL,    ".");
    ip = atoi(ip_tok);
    /*
        NET_IP_BASE : 192.168. (내부 네트워크라고 가정함.)
        NLP_PORT_DIRECT : nmap 192.168.ccc.* -p T:9100 --open
        NLP_PORT_SERVER : nmap 192.168.ccc.* -p T:8888 --open
    */
    info_cnt = nlp_find (ip, NLP_PORT_DIRECT, nlp_list, 0);
    info_cnt = nlp_find (ip, NLP_PORT_SERVER, nlp_list, info_cnt);

    return info_cnt;
}

//------------------------------------------------------------------------------
//
// Direct 연결하여 프린트 할 수 있는 Format으로 데이터 변경 (ZD230D)
//
// mtype : 0 (mac addr), 1 (error)
// msg
//      mtype : 0 -> 00:1e:06:xx:xx:xx
//      mtype : 1 -> err1, err2, ...
//      ch : 0 (left), 1 (right)
//
//------------------------------------------------------------------------------
static void convert_to_zpl (char *sbuf, char mtype, char *msg, char ch)
{
    int len;

    if (mtype) {
        char err[20], *msg_ptr, line = 0;
        int err_len;

        memset (err, 0x00, sizeof(err));
        len     = sprintf (&sbuf[0]  , "%s", "^XA");
        len    += sprintf (&sbuf[len], "%s", "^FO304,20");

        err_len = sprintf (&err[0], "%c ", ch ? '>' : '<');
        msg_ptr = strtok (msg, ",");

        while (msg_ptr != NULL) {
            if ((strlen(msg_ptr) + err_len) > NPL_PRINT_WIDTH) {
                len += sprintf (&sbuf[len], "^FD%s^FS", err);
                memset (err, 0x00, sizeof(err));
                err_len = 0;
                if (line < NPL_PRINT_HEIGHT-1) {
                    line++;
                } else {
                    len += sprintf (&sbuf[len], "%s", "^XZ");
                    len += sprintf (&sbuf[len], "%s", "^XA");
                    line = 0;
                }
                len += sprintf(&sbuf[len], "^FO304,%d", line * 20 + 20);
            }
            err_len += sprintf(&err[err_len], "%s ", msg_ptr);
            msg_ptr  = strtok (NULL, ",");
        }
        if (err_len) {
            len += sprintf (&sbuf[len], "^FD%s^FS", err);
            len += sprintf (&sbuf[len], "%s", "^XZ");
        }
    } else {
        char mac[18], *ptr;

        memset (mac, 0x00, sizeof(mac));
        len  = sprintf (&sbuf[0]  , "%s", "^XA");
        len += sprintf (&sbuf[len], "%s", "^CFC");
        len += sprintf (&sbuf[len], "%s", "^FO310,25");

        toupperstr (msg);
        if ((ptr = strstr (msg, "001E06")) != NULL) {
            len += sprintf (&sbuf[len], "^FD%s^FS",
                    ch == 0 ? "< forum.odroid.com" : "forum.odroid.com >");
        } else {
            len += sprintf (&sbuf[len], "^FD%s^FS", "<< MAC ADDRESS >>");
            ptr = &msg[0];
        }
        len += sprintf (&sbuf[len], "%s", "^FO316,55");
        sprintf(mac, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
            toupper(ptr[0]), toupper(ptr[1]), toupper(ptr[2]), toupper(ptr[3]),
            toupper(ptr[4]), toupper(ptr[5]), toupper(ptr[6]), toupper(ptr[7]),
            toupper(ptr[8]), toupper(ptr[9]), toupper(ptr[10]), toupper(ptr[11]));
        len += sprintf (&sbuf[len], "^FD%s^FS", mac);
        len += sprintf (&sbuf[len], "%s", "^XZ");
    }
    dbg_msg ("msg : %s, size = %d\n", sbuf, len);
}

//------------------------------------------------------------------------------
//  Network label printer에 MAC 또는 에러메세지를 출력한다.
//  입력된 주소를 가지고 connect 상태를 확인한다.
//  실패시 현재 자신의 주소를 확인 후 자신의 주소를 기준으로 nmap을 실행한다.
//
//  NLP_PORT_SERVER설정의 경우
//  TCP/IP port 8888로 응답이 있고 mac addr이 00:1e:06:xx:xx:xx인 경우 해당함.
//  기존의 Label Printer(GC420d)는 USB로 바로 연결되어야 하므로 Server역활인 ODROID-C4
//  에서 데이터를 받아 프린터에 전송하는 방식으로 동작시킴.
//
//  nmap 192.168.xxx.xxx -p T:8888 --open
//
//  NLP_PORT_DIRECT설정의 경우
//  TCP/IP port 9100으로 응답이 있는 경우 ZD230이라고 간주한다.
//  nmap 192.168.xxx.xxx -p T:9100 --open
//
//  scan되어진 ip중 연결되는 ip가 있다면 프린터라고 간주한다.
//  프린터에 메세지를 출력하고 출력이 정상인지 확인한다.
//  정상적으로 연결되어진 ip를 입력되어진 주소영역에 저장한다.
//
//  mtype : 0 (mac addr), 1 (error)
//  msg
//      mtype : 0 -> 00:1e:06:xx:xx:xx
//      mtype : 1 -> err1, err2, ...
//      ch : 0 (left), 1 (right)
//
//  성공 return 1, 실패 return 0
//------------------------------------------------------------------------------
static int nlp_write (const struct nlp_info *nlp_info, char mtype, char *msg, char ch)
{
    int nlp_fp, len;
    char nlp_ver[20], sbuf[4096];

    memset(nlp_ver , 0, sizeof(nlp_ver));
    memset(sbuf, 0, sizeof(sbuf));

    if (!(nlp_fp = nlp_connect (nlp_info))) {
        dbg_msg ("Network Label Printer connect error. ip = %s\n", nlp_info->ip);
        return 0;
    }

    if (sizeof(sbuf) < strlen(msg)) {
        dbg_msg ("msg alloc error!\n");
        return 0;
    }

    // 받아온 문자열 합치기
    if (nlp_info->port == NLP_PORT_SERVER) {
        nlp_version (nlp_info, nlp_ver);

        // send mac address size control
        if (!mtype) {
            if (strlen (msg) > 12)
                msg [12] = 0x00;
            tolowerstr (msg);
        }

        if (!strncmp(nlp_ver, "202204", strlen("202204")-1)) {
            // charles modified version
            dbg_msg ("new version nlp-printer. ver = %s\n", nlp_ver);
            sprintf(sbuf, "%s-%c,%s",
                            ch    ? "right" : "left",
                            mtype ?     'e' : 'm',
                            msg);
        } else {
            dbg_msg ("old version nlp-printer.\n");
            // original version
            if (mtype)
                sprintf(sbuf, "error,%c,%s", ch ? '>' : '<', msg);
            else
                sprintf(sbuf, "mac,%s", msg);
        }
    }
    else
        convert_to_zpl (sbuf, mtype, msg, ch);

    // 받아온 문자열 전송
    if ((len = write (nlp_fp, sbuf, strlen(sbuf))) != (int)strlen(sbuf)) {
        dbg_msg ("send bytes error : buf = %ld, write = %d\n", strlen(sbuf), len);
    }

    // 소켓 닫음
    nlp_disconnect (nlp_fp);

    return 1;
}

//------------------------------------------------------------------------------
//
// ping검사로 현재 연결이 유지되고 있는지 확인
//
//------------------------------------------------------------------------------
int nlp_status (const char *nlp_ip)
{
    char buf[128];
    FILE *fp;

    memset (buf, 0x00, sizeof(buf));
    sprintf(buf, "ping -c 1 -w 1 %s", nlp_ip);

    if ((fp = popen(buf, "r")) != NULL) {
        memset(buf, 0x00, sizeof(buf));
        while (fgets(buf, 2048, fp)) {
            if (NULL != strstr(buf, "1 received")) {
                pclose(fp);
                return 1;
            }
        }
        pclose(fp);
    }
    dbg_msg ("%s = false\n", __func__);
    return 0;
}

//------------------------------------------------------------------------------
//
// 현재 scan되어진 network label printer 정보를 표시한다.
//
//------------------------------------------------------------------------------
void nlp_scan_list (const struct nlp_info *nlp_info)
{
    struct nlp_info *nlp_list = (struct nlp_info *)nlp_info->list;

    if (nlp_list) {
        int i;
        dbg_msg ("[Network label printer list]\n");

        for(i = 0; i < NLP_LIST_MAX; i++) {
            if ((nlp_list + i)->port != 0) {
                dbg_msg ("%d) CONNECT: %d, PORT : %d, IP : %s, MAC : %s\n",
                    i + 1,
                    (nlp_list + i)->conn,
                    (nlp_list + i)->port,
                    (nlp_list + i)->ip,
                    (nlp_list + i)->mac);
            }
        }
    } else {
        dbg_msg ("[Not found network label printer]\n");
    }

}

//------------------------------------------------------------------------------
//
// NLP Library의 global변수를 사용하여 프린트 진행.
//
// BoardInfo.conn이 1이되기 위하여서는 nlp_init이 선행되어야 함.(get_board_info실행)
//
//------------------------------------------------------------------------------
int nlp_printf (const struct nlp_info *nlp_info, const char mtype, const char *msg, const char ch)
{
    // 메모리를 할당하여 메세지를 저장한다.
    // strtok 함수를 사용하기 때문에 const형이 오면 segmant fault가 발생한다.
    int  msg_size = strlen(msg)+1, ret = 0;
    char *msg_buf = (char *)malloc(msg_size);

    if (msg_buf == NULL) {
        dbg_msg ("Message buffer allocate error!.\n");
        return 0;
    }
    memset (msg_buf,   0, msg_size);
    memcpy (msg_buf, msg, msg_size);

    /* 연결되어진 nlp가 있고, ping이 정상인 경우 print */
    if (nlp_info->conn && nlp_status(nlp_info->ip))
        ret = nlp_write (nlp_info, mtype, msg_buf, ch);

    if (msg_buf)
        free(msg_buf);

    return ret;
}

//------------------------------------------------------------------------------
// 입력된 nlp_info변수의 주소/포트/MAC address를 기준으로 접속함.
//
// 모든 입력변수가 NULL인 경우 9100, 8888 포트의 순서로 검색하여 제일 처음 찾은 NLP를 기준으로 동작함.
//
// 다른 값이 있는 경우 해당 조건이 맞는 NLP를 검색하도록 함.
//
// 성공 return nlp_count, 실패 return 0
//------------------------------------------------------------------------------
int nlp_init (struct nlp_info *nlp_info, const char *if_name)
{
    int info_cnt, cnt, info_size = sizeof(struct nlp_info) * NLP_LIST_MAX;
    struct nlp_info *p_info = (struct nlp_info *)malloc(info_size);

    /* 기존에 사용중이었던 경우에는 메로리 초기화 후 다시 실행하도록 한다. */
    if (nlp_info->list)
        nlp_deinit(nlp_info);

    /* 메모리 할당 여부 확인 */
    if (p_info) {
        memset (p_info, 0, sizeof(info_size));
    } else {
        printf ("%s : Allocation error!\n", __func__);
        return 0;
    }
    /*
        p_info변수에 scan되어진 network label printer정보와 찾은 개수를 받아온다.
    */
    if ((info_cnt = nlp_scan (p_info, if_name))) {
        for (cnt = 0; cnt < info_cnt; cnt++) {
            // 만약 같은 라인에 연결되어진 프린터가 많은 경우 특정 프린터를 찾기위하여 사용함.
            if (      (nlp_info->port) != 0  ||
                (atoll(nlp_info->mac)  != 0) ||
                (atoll(nlp_info->ip)   != 0)) {
                if (nlp_info->port) {
                    dbg_msg ("found port = %d, sacn port = %d\n",
                                nlp_info->port, (p_info->port + cnt));
                    if (nlp_info->port != (p_info + cnt)->port)
                        continue;
                }
                if (atoll(nlp_info->mac) != 0) {
                    /* 대문자로 변경하여 비교한다. */
                    toupperstr(nlp_info->mac);
                    dbg_msg ("found mac = %s, sacn mac = %s\n",
                                nlp_info->mac, (p_info->mac + cnt));

                    if (strncmp (nlp_info->mac, (p_info + cnt)->mac, strlen(nlp_info->mac)))
                        continue;
                }
                if (atoll(nlp_info->ip)  != 0) {
                    dbg_msg ("found ip = %s, sacn ip = %s\n",
                                nlp_info->ip, (p_info->ip + cnt));
                    if (strncmp (nlp_info->ip, (p_info + cnt)->ip, strlen(nlp_info->ip)))
                        continue;
                }
            }
            /* 사용되고 있음을 표시 */
            memset (nlp_info, 0, sizeof(struct nlp_info));
            (p_info + cnt)->conn = 1;
            memcpy (nlp_info, (p_info + cnt), sizeof(struct nlp_info));
            /* Scan list정보를 보관 */
            nlp_info->list = (void *)p_info;

            printf ("Found network label printer (count = %d).\n", info_cnt);
            dbg_msg ("Found network label printer (count = %d).\n", info_cnt);
            printf ("Connect info : IP(%s), PORT(%d) MAC(%s)\n",
                        (p_info + cnt)->ip, (p_info + cnt)->port, (p_info + cnt)->mac);
            dbg_msg ("Connect info : IP(%s), PORT(%d) MAC(%s)\n",
                        (p_info + cnt)->ip, (p_info + cnt)->port, (p_info + cnt)->mac);

            return info_cnt;
        }
    }
    if (p_info)
        free (p_info);
    dbg_msg ("%s : Can't found network label printfer!!\n", __func__);
    return 0;
}

//------------------------------------------------------------------------------
void nlp_deinit (struct nlp_info *nlp_info)
{
    if (nlp_info->list)
        free (nlp_info->list);
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
