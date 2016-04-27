#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<getopt.h>
#include<pcap.h>
#include<mysql/mysql.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<net/ethernet.h>
#include<sys/types.h>
#include<netinet/if_ether.h>
#include<netinet/ether.h>


#define def_host_name "us-cdbr-iron-east-03.cleardb.net" /* host to connect to (default = localhost) */
#define def_user_name "bbbb6dc727647c" /* user name (default = your login name) */
#define def_password "c0b60c6a" /* password (default = none) */
#define def_db_name "heroku_89678d1e4934514" /* database to use (default = none) */
#define COMMAND_SIZE 73
#define SIZE_ETHERNET 14
#define	T_DATA 0x2
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_IPV6		0x86dd	/* IPv6 */
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define FC_TYPE(fc) (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc) (((fc) >> 4) & 0xF)
#define FC_TO_DS(fc) ((fc) & 0x0100)
#define FC_FROM_DS(fc) ((fc) & 0x0200)
#define DATA_FRAME_IS_QOS(x) ((x) & 0x08)
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)

typedef u_int tcp_seq;

/***************************************
 *                                     * 
 *   Structs to represent headers      *
 *                                     *
 ***************************************/
typedef struct radiotap_header {
    u_int8_t	it_version;	/* set to 0 */
    u_int8_t	it_pad;
    u_int16_t	it_len;		/* entire length */
    u_int32_t	it_present;	/* fields present */
} radiotap_h;
typedef struct wifi_header {
    u_int16_t fc;
    u_int16_t duration;
    const struct ether_addr dst_addr;
    const struct ether_addr src_addr;
    u_int8_t bssid[6];
    u_int16_t seq_ctrl;
} wifi_h;

void change_channel(int new_channel);
void print_packet(const u_char*, radiotap_h*, wifi_h*);
void getCommandLine(int, char**, char**, char*);
void accessDatabase();
void process_result_set(MYSQL *conn, MYSQL_RES *res_set, char *macs[]);
