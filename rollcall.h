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
//#define ETHER_ADDR_LEN 6

/***************************************
 *                                     * 
 *   Structs to represent headers      *
 *                                     *
 ***************************************/
typedef struct ethernet_h_tag{
    const struct ether_addr ether_dest_host; //the destination host address
    const struct ether_addr ether_src_host; //the source host address
    u_short ether_type; //to check if its ip etc
}ethernet_h;

typedef struct ip_h_tag{
    unsigned char ip_vhl; //assuming its ipv4 and header length more than 2
    unsigned char service; //type of service
    unsigned short total_len; //total length
    unsigned short identification; // identification
    u_short ip_off; //offset field
    u_char ttl; // time to live value
    u_char ip_protocol; // the protocol
    u_short sum; //the checksum
    struct in_addr ip_src;
    struct in_addr ip_dst;

    #define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)        (((ip)->ip_vhl) >> 4)
}ip_h;


typedef struct tcp_h_tag{
    u_short src_port;   /* source port */
    u_short dst_port;   /* destination port */
}tcp_h;

void print_packet(const u_char*, int, ethernet_h*, ip_h*, tcp_h*);
void getCommandLine(int, char**, char**, char*);
void accessDatabase();
void process_result_set(MYSQL *conn, MYSQL_RES *res_set, char *macs[]);
