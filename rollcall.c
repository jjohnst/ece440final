/* Rollcall File For ECE 440
 *  
 * Created by: Morgan McEntire
 *             Ben Hindman
 *             Isiah Hamilton
 *             Josh Johnston
 *
 * Known Bugs:
 *      filter doesn't work
 *
 */

#include"rollcall.h"

MYSQL *conn; //Pointer to connection handler

int main(int argc, char *argv[]){
    char *device=NULL, *filter=NULL, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program compiled_filter; //Compiled filter expression
    bpf_u_int32 mask, net;              //Subnet mask and IP addr
    struct pcap_pkthdr header;          //Header that pcap gives
    const u_char *packet;               //Actual packet

    /*Header Structs*/
    ethernet_h *ethernet=NULL;
    ip_h *ip=NULL;
    tcp_h *tcp=NULL;

    filter="ether src f4:f2:6d:17:23:e8 && tcp";

    //Grab the default wireless device
    if(argc<2){
        printf("Not enough arguments. Do -h for help.\n");
        exit(1);
    }
    getCommandLine(argc, argv, &device, errbuf);
    if(device==NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\nfilter: %s\n", device, filter);


    //Open device for sniffing
    handle=pcap_open_live(device, BUFSIZ, 1 /*promisc mode*/, 1000, errbuf);
    if(handle==NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return(2);
    }
  
    //Get the network address and network mask
    pcap_lookupnet(device, &net, &mask, errbuf);

    //Compiles and sets the filter to sniff for
    if(pcap_compile(handle, &compiled_filter, filter, 0, mask)==-1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &compiled_filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }
    
    
    packet=NULL;
    //Grab a packet
    while(packet==NULL)
        packet = pcap_next(handle, &header);
  
    //Printing packet information
    print_packet(packet, header.len, ethernet, ip, tcp);
    
    //Close the session
    pcap_close(handle);

    accessDatabase();
    
    return(0);
}

void getCommandLine(int argc, char **argv, char **device, char *errbuf){
    int c;
    while ((c = getopt(argc, argv, "d:fh")) != -1)
	    switch(c) {
            case 'd': *device=strdup(optarg); break;
            case 'f': *device=pcap_lookupdev(errbuf); break;
            case 'h':
            default: 
                printf("Rollcall command line options:\n");
                printf("   -d device    device to sniff on\n");
                printf("   -f           uses default device to sniff\n");
                printf("   -h           shows this menu\n");
                printf("------------------------------\n");
                printf("Only use -d or -f. Not both.\n");
                exit(1);
        }
}


void accessDatabase(){
    char *addrs[4];
	char *present[2];
	char *absent[2];
	char command[COMMAND_SIZE];
	MYSQL_RES *res_set;
	int i, j, here;

	conn = mysql_init (NULL);
	if (conn == NULL){
		fprintf (stderr, "mysql_init() failed (probably out of memory)\n");
		exit (1);
	}

	if (mysql_real_connect (
				conn, //Pointer to connection handler 
				def_host_name, //Host to connect to 
				def_user_name, //User name 
				def_password, //Password 
				def_db_name, //Database to use 
				0, //Port (use default) 
				NULL, //Socket (use default) 
				0) //Flags (none) 
			== NULL)
	{
		fprintf (stderr, "mysql_real_connect() failed:\nError %u (%s)\n", mysql_errno (conn), mysql_error (conn));
		exit (1);
	}

	if (mysql_query (conn, "SELECT * from student") != 0){
		printf("mysql_query() failed\n");
    }else{
		res_set = mysql_store_result (conn); // generate result set
		if (res_set == NULL){
			printf("mysql_store_result() failed\n");
        }else{
			//process result set, then deallocate it
			process_result_set (conn, res_set, addrs);
			mysql_free_result (res_set);
		}
	}

	//based on reading packets
	present[0] = addrs[0];
	present[1] = addrs[1];

	//determine who's absent
	//look at each value in the addr array and determine if it is in the present array
	for(i =0; i < 4; i++){
		for(j=0; j < 2; j++){
			if(strcmp(addrs[i], present[j]) == 0){
				//student is present
				here = 1;
			}
		}

		if(here == 0){
			//mark absent in database
			snprintf(command, COMMAND_SIZE, "UPDATE student SET absences = absences + 1 WHERE mac='%s'", addrs[i]);
			if (mysql_query (conn, command) != 0){
				printf("mysql_query() failed\n");
            }else{
				printf("Student marked absent\n");
			}
		}

		here =0;
	}
	mysql_close (conn);
}

void process_result_set(MYSQL *conn, MYSQL_RES *res_set, char *macs[]){
	MYSQL_ROW row;
	unsigned int i=0;

	while ((row = mysql_fetch_row (res_set)) != NULL){
		macs[i]= row[1];
		i++;
		
		// for (i = 0; i < mysql_num_fields (res_set); i++)
		// {
		// 	if (i > 0)
		// 		fputc ('\t', stdout);
		// 	printf ("%s", row[i] != NULL ? row[i] : "NULL");
		// }
		// fputc ('\n', stdout);
	}

	if (mysql_errno (conn) != 0){
		printf("mysql_fetch_row() failed\n");
	}else{
		printf ("%lu rows returned\n", (unsigned long) mysql_num_rows (res_set));
	}
}

void print_packet(const u_char *packet, int size, ethernet_h *ethernet, ip_h *ip, tcp_h *tcp){
    printf("\n\n----------- Packet ------------\n");
    printf(" Size: %d bytes", size);

    ethernet = (ethernet_h*) (packet);
    printf("\n MAC src: %s", ether_ntoa(&ethernet->ether_src_host));
    printf("\n MAC dest: %s", ether_ntoa(&ethernet->ether_dest_host));

    ip = (ip_h*) (packet + sizeof(ethernet_h));
    printf("\n IP src: %s", inet_ntoa(ip->ip_src));
    printf("\n IP dest: %s", inet_ntoa(ip->ip_dst));

    tcp = (tcp_h*) (packet + sizeof(ethernet_h) + sizeof(ip_h));
    printf("\n Src port: %d", ntohs(tcp->src_port));
    printf("\n Dst port: %d\n", ntohs(tcp->dst_port));

    printf("-------------------------------\n\n");
}
