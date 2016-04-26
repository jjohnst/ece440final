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

    //Header Structs
    radiotap_h *radiotap=NULL;
    wifi_h *wifi=NULL;

    //What to filter on
    filter="wlan";

    //Error checking for number of arguments
    if(argc<2){
        printf("Not enough arguments. Do -h for help.\n");
        exit(1);
    }

    //Grab the default wireless device
    getCommandLine(argc, argv, &device, errbuf);
    if(device==NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\nfilter: %s\n", device, filter);
  
    //Get the network address and network mask
    pcap_lookupnet(device, &net, &mask, errbuf);

    //Create and activate handle to sniff network
    handle=pcap_create(device, errbuf);
    pcap_set_rfmon(handle, 1);
    pcap_set_snaplen(handle, 2048); //Snapshot length
    pcap_set_timeout(handle, 1000); // Timeout in miliseconds
    pcap_activate(handle);

    //Compiles and sets the filter to sniff for
    if(pcap_compile(handle, &compiled_filter, filter, 0, mask)==-1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &compiled_filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }
    
    
    //Wait until you can actually grab a packet
    packet=NULL;
    while(packet==NULL)
        packet = pcap_next(handle, &header);
  
    //Print packet information
    print_packet(packet, radiotap, wifi);
    
    //Close the session
    pcap_close(handle);

    //Thrown at the end for now just cause
    accessDatabase();
    
    return(0);
}

/* Purpose: Grab the command line arguments provided
 *
 * Arguments: argc, argv, device name, error array
 *
 * Returns: N/A
 *
 */
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


/* Purpose: Access the database to determine wether a student was present or absent
 *
 * Arguments: N/A
 *
 * Returns: N/A
 *
 */
void accessDatabase(){
    char *addrs[4];
	char *present[2];
	//char *absent[2];
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

/* Purpose: Grabs the contents of the database rows
 *
 * Arguments: databas connection, something, mac address array
 *
 * Returns: N/A
 *
 */
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


/* Purpose: To print out the information in the packet that was sniffed
 *
 * Arguments: packet, size of the packet, ethernet struct, ip struct,
 *            tcp struct
 *
 * Returns: N/A
 *
 */
void print_packet(const u_char *packet, radiotap_h *radiotap, wifi_h *wifi){
    int size_radiotap;
    
    printf("\n\n----------- Packet ------------\n");

    radiotap=(struct radiotap_header *)packet;
    size_radiotap=radiotap->it_len;
    printf("Radiotap header length: %d\n", size_radiotap);

    //Calculate 802.11 header length
    wifi=(wifi_h *)(packet + size_radiotap);
    printf("WLAN src: %s\n", ether_ntoa(&wifi->src_addr));
    printf("WLAN dst: %s\n", ether_ntoa(&wifi->dst_addr));

    printf("-------------------------------\n\n");
}
