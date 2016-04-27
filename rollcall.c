/*
* Program: rollcall.c
* Name: Isiah Hamilton, Ben Hindman, Joshua Johnston, Morgan McEntire
* Date: 4/27/2016
* Purpose: Scans eduroam for available channels and then searches for MAC addresses
* across all channels and logs missing MACs to log file
* Assumptions: OS X ONLY, MAC addresses are in DB, rollcall.h has DB connection info,
* uses mysql c connector
*/

#include "rollcall.h"

int main(int argc, char *argv[]){
    char *device=NULL, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program compiled_filter; //Compiled filter expression
    bpf_u_int32 mask, net;              //Subnet mask and IP addr
    struct pcap_pkthdr header;          //Header that pcap gives
    const u_char *packet;               //Actual packet
    char *addrs[CLASS_SIZE];
    int i, j, filter_size;
    int *channels;
    FILE *fp = fopen("absences.log","w");
    
    const char s1[] = "wlan src ";      //used in pcap filter

    /*Header Structs*/
    radiotap_h *radiotap = NULL;
    wifi_h *wifi = NULL;
    
    // GET MAC ADDRESSES 
    getMacsDb(addrs);
    //hardcoded backup
    // addrs[0] = "3c:15:c2:ed:b3:dc";
    // addrs[1] = "f4:5c:89:89:fd:93";
    // addrs[2] = "5c:c5:d4:58:64:66";
    // addrs[3] = "f4:f2:60:17:23:e8";
    // addrs[4] = "a4:5e:60:e7:a3:15";

    int num_macs = sizeof(addrs)/sizeof(addrs[0]);
    //printf("Number of macs = %d\n", num_macs);
    /*for(i=0; i < num_macs; i++){
        printf("%s\n",addrs[i]);
    }*/

    //Get the number of channels to search and what they are
    int ch_length = 0;
    channels=getChannels(&ch_length);
    
    //Grab the default wireless device
    getCommandLine(argc, argv, &device, errbuf);
    if(device==NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
  
    pcap_lookupnet(device, &net, &mask, errbuf);

    filter_size = 100;// +1 for \0 terminator 
    char filter[filter_size];
    //length of the array of channels
    for (i=0; i < ch_length; i++) {
        
        // close previous session
        if (i>0) {
            pcap_close(handle);
        }
        //Change channels to search for MAC address
        change_channel(channels[i]);
        
        //Recreate handle
        handle = pcap_create(device, errbuf);
        pcap_set_rfmon(handle, 1);
        if (pcap_set_promisc(handle, 1) == PCAP_ERROR_ACTIVATED) /* Capture packets that are not yours */
            printf("Could not set promiscious\n");
        pcap_set_snaplen(handle, 2048); /* Snapshot length */
        pcap_set_timeout(handle, 1000); /* Timeout in milliseconds */
        pcap_activate(handle);
        
        
        for (j = 0; j < num_macs; j++) {
            if(addrs[j] != NULL){
                //create pcap filter
                strcpy(filter, s1);
                strcat(filter, addrs[j]);
                
                printf("Looking for: %s\n",addrs[j]);
                
                //Compiles and sets the filter to sniff for
                if(pcap_compile(handle, &compiled_filter, filter, 0, mask)==-1){
                    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
                    return(2);
                }
                if (pcap_setfilter(handle, &compiled_filter) == -1) {
                    fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
                    return(2);
                }
                
                int count = 0;
                packet=NULL;
                //Grab a packet
                while (packet==NULL && count<3) {
                    packet = pcap_next(handle, &header);
                    count++;
                }
                
                //Printing packet information
                if (packet!=NULL){
                    print_packet(packet, header.len, radiotap, wifi); 
                    //set addrs[j] to NULL if MAC has been found
                    addrs[j] = NULL;  
                }
            } 
        }       
    }
    
    for (i=0;i<num_macs;i++) {
        if (addrs[i]!=NULL) {
            fprintf(fp, "%s\n", addrs[i]);
            //fprintf(fp, "\n");
        }
    }
    fclose(fp);
    free(channels);
    return(0);
}

/* Purpose: Grab command line functions from the user
 *
 * Parameters: argc, argv, variable to store device name, error buffer
 *
 * Returns: N/A
 *
 */
void getCommandLine(int argc, char **argv, char **device, char *errbuf){
    int c;
    while ((c = getopt(argc, argv, "d:f")) != -1)
	    switch(c) {
            case 'd': *device=strdup(optarg); break;
            case 'f': *device=pcap_lookupdev(errbuf); break;
            default: 
                printf("Rollcall command line options:\n");
                printf("   -d device    device to sniff on\n");
                printf("   -f           uses default device to sniff\n");
                printf("------------------------------\n");
                printf("Only use -d or -f. Not both.\n");
                exit(1);
        }
}
/*
* Purpose: Connect to DB and get mac addresses. Then it stores them
*          in an array passed by reference
*
* Parameters: Array to hold MAC addresses
*
* Returns: Theoretically nothing, but it changes the mac_addrs to update
*          with the MAC addresses from the database by calling process_result_set
*/
void getMacsDb(char *mac_addrs[]){
    MYSQL_RES *res_set;

    //Initialize MySQL connection
    conn = mysql_init (NULL);
    if (conn == NULL){
        fprintf (stderr, "mysql_init() failed (probably out of memory)\n");
        exit (1);
    }

    //Connect to the database
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

    //Send the query to the database to grab the table
    if (mysql_query (conn, "SELECT * from student") != 0){
        printf("mysql_query() failed\n");
    }else{
        res_set = mysql_store_result (conn); // generate result set
        if (res_set == NULL){
            printf("mysql_store_result() failed\n");
        }else{
            //process result set, then deallocate it
            process_result_set (conn, res_set, mac_addrs);
            mysql_free_result (res_set);
        }
    }

    mysql_close (conn);
}

/* Purpose: Get MAC addresses from database and store in macs array
 *
 * Parameters: conn, res_set, array for MAC addresses
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
    }

    if (mysql_errno (conn) != 0){
        printf("mysql_fetch_row() failed\n");
    }else{
        //printf ("%lu rows returned\n", (unsigned long) mysql_num_rows (res_set));
    }
}

/*
*  Purpose: Changes channels on the access point using OS X airport utility
*           WARNING: will disconnect you from network and
*           you will need to manually reconnect
*
* Parameters: Channel to connect to
*
* Returns: N/A
*
*/

void change_channel(int new_channel) {
    /*if mac with airport utility*/
    
    char *command1 = "airport --disassociate";
    FILE *fp = popen(command1, "r");
    pclose(fp);
    printf("Disassociated with previous channel.\n");

    char *command2 = malloc(20);
    sprintf(command2, "airport --channel=%d",new_channel);

    fp = popen(command2, "r");
    pclose(fp);
    
    printf("Now on channel: %d.\n\n", new_channel);
    free(command2);
    
}

/* Purpose: Prints out the packet information - the MAC address it found
 *          and where it was transmitting to.
 *
 * Parameters: the packet, the size, the radiotap header, and the wifi header
 *
 * Returns: N/A
 *
 */
void print_packet(const u_char *packet, int size, radiotap_h *radiotap, wifi_h *wifi){
    int size_radiotap;
    
    //printf("\n\n----------- Packet ------------\n");
    
    /* Get Radiotap header length (variable) */
    radiotap = (struct radiotap_header*)(packet);
    size_radiotap = radiotap->it_len;
    
    //printf("\nRadiotap header length: %d\n", size_radiotap);
    
    /* Calculate 802.11 header length (variable) */
    wifi = (wifi_h *)(packet + size_radiotap);
    
    printf("  Found %s ", ether_ntoa(&wifi->sa));
    printf("transmitting to %s\n", ether_ntoa(&wifi->da));
    
    
    /*printf(" Size: %d bytes", size);
    
    radiotap = (radiotap_h*) (packet);
    
    printf("\n MAC src: %s", ether_ntoa(&ethernet->ether_src_host));
    printf("\n MAC dest: %s", ether_ntoa(&ethernet->ether_dest_host));
    
    ip = (ip_h*) (packet + sizeof(ethernet_h));
    printf("\n IP src: %s", inet_ntoa(ip->ip_src));
    printf("\n IP dest: %s", inet_ntoa(ip->ip_dst));
    
    tcp = (tcp_h*) (packet + sizeof(ethernet_h) + sizeof(ip_h));
    printf("\n Src port: %d", ntohs(tcp->src_port));
    printf("\n Dst port: %d\n", ntohs(tcp->dst_port));
     */
    //printf("-------------------------------\n\n");
}

/*
*  Purpose: Grabs the available channels using airport. It stores the channels
*           in an array and keeps track of how many channels there are.
*
*  Parameters: Number of channels (passed by reference to have two returns)
*
*  Returns: The array of channels. Also changes count
*
*/
int* getChannels(int *count){
    char path[1035];
    char channel[4];
    char full_channel[4];
    int *ichannels=malloc(50*sizeof(int)); //freed in main program at bottom
    FILE *fp;
    int temp;
    int i;
    int check;
    
    //Open airport and grep for eduroam
    fp=popen("airport -s | grep eduroam", "r");
    if(fp==NULL){
        printf("Failed to run command to grab channels.\n");
        exit(1);
    }
    
    printf("Channels: ");
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
        //these values come from the length of the output string from airport
        //channel numbers always start at 56 and can be 3 chars long
        channel[0] = path[56];
        channel[1] = path[57];
        channel[2] = path[58];
        channel[3] = '\0';

        //Combine to a string then convert to an int
        sprintf(full_channel, "%c%c%c",channel[0],channel[1],channel[2]);
        temp = (int) strtol(full_channel, (char **)NULL, 10);
        
        //Grabs only unique channels
        check = 0;
        i=0;
        while (i < *count) {
            if (temp==ichannels[i]) {
                check = 1;
            }
            i++;
        }
        if (check==0) {
            ichannels[(*count)++] = temp;
            //Prints the channels
            printf("%d, ",ichannels[(*count)-1]);
        }
        
    }
    printf("\n");
    /* close */
    pclose(fp);
    
    return ichannels;
}
