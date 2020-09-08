/********************************************************************
 *	IPK projekt: Sniffer paketov                         	        *
 *	                                        	                    *
 *	Author(s): Juraj Lazorik (xlazor02)                             *
 *	Date: 01.05.2020                                                *
 *	VUT FIT Brno                                                    *
 *                                                                  *
 *******************************************************************/

#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>
#include<unistd.h>  
#include<time.h>
#include<netdb.h>
#include<string.h>

#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ipv4 header
#include<netinet/ip6.h>    //Provides declarations for ipv6 header

#define cacheSize 8
#define IPv4 4
#define IPv6 6

//functions definitions
void my_packet_handler(unsigned char *args,const struct pcap_pkthdr *header,const unsigned char *packet);
void print_tcp_packet(const unsigned char * Buffer, int Size,int IP);
void print_udp_packet(const unsigned char * Buffer, int Size,int IP);
void printDevices();
void PrintData (const unsigned char* data , int Size);
void resolve(struct in_addr IPaddr);
void resolve6(struct in6_addr IPaddr);
char* IPtoHostName(char* IP);
char* IPtoHostName6(char* IP);

//global variables
char node[NI_MAXHOST]; //global variable which hold hostname
int cnt = 0; //global variable for byt counting
int total = 1; //packet number
char ipCacheArray[cacheSize][NI_MAXSERV]; //ip array for caching
char hostnameCacheArray[cacheSize][NI_MAXHOST]; //hostname array for caching
int cachePointer = 0; //cache array pointer
bool resolveFlag = false; //option flag for resolving 
bool showDnsCache = false; //option for showing dns cache content

/*********************************************************************************
*
*	Base for using pcap functions in main
*
*	Title: Packet Sniffer Code in C using sockets | Linux
*	Author: Silver Moon
*	Availability: https://www.binarytides.com/packet-sniffer-code-c-linux/
*
*********************************************************************************/

/*********************************************************************************
*
*	Base for using pcap functions and filter in main
*
*	Title: Using libpcap in C
*	Author: NanoDano
*	Availability: https://www.devdungeon.com/content/using-libpcap-c
*
*********************************************************************************/

int main(int argc, char *argv[])
{
    int option;
    bool tcpFlag = false;
    bool udpFlag = false;
    bool portFlag = false;
    char* device = "";
    char* port;
    int packet_count_limit = 1; //default print only 1 packet

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle; //handle of the device that will be sniffed
    struct bpf_program fp; //structure needed for filtering
    char filter_exp[32]=""; //filter expression
    
    int timeout_limit = 200; //the packet buffer timeout in milliseconds 

	//loop for argument parsing
	while ((option = getopt(argc,argv,":i:p:turdn:")) != -1 )
	{
		switch (option)
		{
		case 'i':
            device = optarg;
			break;
		case 'p':
            portFlag = true;
            port = optarg;
			break;
        case 't':
            tcpFlag = true;
			break;
        case 'u':
            udpFlag = true;
			break;
        case 'n':
            packet_count_limit = atoi(optarg);
			break;
        case 'r':
            resolveFlag = true;
            break;
        case 'd':
            showDnsCache = true;
            break;
		case ':':
			printf("Options -i -p -n need value\n");
			printf("Try: ./ipk-sniffer -i [interface] -t -u -p 80 -n 10\n");
			return -1;
			break;
		case '?':
			printf("Unknown option %c\n", optopt);
			printf("Try: ./ipk-sniffer -i [interface] -t -u -p 80 -n 10\n");
			return -1;
			break;
		default:
			printf("Unknown error\n");
			printf("Try: ./ipk-sniffer -i [interface] -t -u -p 80 -n 10\n");
			return -1;
			break;
		}
	}

    //without interface input
    if (*device == '\0'){
        printDevices();
    }else
    {
        //program logic

        if (device == NULL) {
            printf("Error finding device: %s\n", error_buffer);
            return -1;
        }
        
        //open a device for capturing in promiscuous mod
        handle = pcap_open_live(device,BUFSIZ,1,timeout_limit,error_buffer);

        if (handle == NULL) 
        {
            printf("Couldn't open device %s : %s\n" , device , error_buffer);
            return -1;
        }

        //filter expression setting
        if(portFlag) //with port switch
        {
            //tcp and udp filter setting
            if((tcpFlag && udpFlag) || (!tcpFlag && !udpFlag))
            {   
                strcat(filter_exp, "(tcp or udp) and port ");
                strcat(filter_exp, port);
            }else
            {
                if (tcpFlag)
                {
                    strcat(filter_exp, "tcp and port ");
                    strcat(filter_exp, port);
                }
                if (udpFlag)
                {
                    strcat(filter_exp, "udp and port ");
                    strcat(filter_exp, port);
                }
            }
        }else //without port switch
        {
            //tcp and udp filter setting
            if((tcpFlag && udpFlag) || (!tcpFlag && !udpFlag))
            {
                strcat(filter_exp, "tcp or udp");
            }else
            {
                if (tcpFlag)
                {
                    strcat(filter_exp, "tcp");
                }
                if (udpFlag)
                {
                    strcat(filter_exp, "udp");
                }
            }
        }

        //compile a filter expression  
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
        {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return -1;
	    }

        //apply the filter  
	    if (pcap_setfilter(handle, &fp) == -1) 
        {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return -1;
        }

        //process packets from a live capture(and calling packet handler)
        pcap_loop(handle, packet_count_limit, my_packet_handler, NULL);
    }
    //end program
    return 0;
}

//printing all active interfaces
void printDevices(){ 

    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs,*tmp;
    int i = 1;

    //get a list of capture devices
    pcap_findalldevs(&devs, ebuf);

    for(tmp=devs;tmp;tmp=tmp->next)
    {
        printf("%d: %s\n",i++,tmp->name);
       
    }

    exit(0);

}

/*********************************************************************************
*
*	Base for functions: my_packet_handler/print_tcp_packet/print_udp_packet
*
*	Title: Packet Sniffer Code in C using sockets | Linux
*	Author: Silver Moon
*	Availability: https://www.binarytides.com/packet-sniffer-code-c-linux/
*
*********************************************************************************/

/*********************************************************************************
*
*	Base for functions(IPv6): my_packet_handler/print_tcp_packet/print_udp_packet
*
*	Title: Can I use pcap library for receiving ipv6 packets?
*	Author: Flexo♦
*	Availability: https://stackoverflow.com/questions/6256821/can-i-use-pcap-library-for-receiving-ipv6-packets
*
*********************************************************************************/

//function for packet handling
void my_packet_handler(unsigned char *args,const struct pcap_pkthdr *header,const unsigned char *packet)
{

    printf("%i.",total++); //packet number

    //getting packet timestamp from packet
    char rec_time[16];
    strftime(rec_time, 16 , "%H:%M:%S", localtime(&header->ts.tv_sec));
    printf("[%s.%.6ld] ", rec_time, header->ts.tv_usec);


    //getting the Header part of this packet
    struct ether_header *eptr = (struct ether_header*)packet;
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    struct ip6_hdr *iph6 = (struct ip6_hdr*)(packet + sizeof(struct ethhdr));
    int size = header->len;

    //getting type of packet (IPv4/IPv6)
    switch (ntohs(eptr->ether_type)) 
    {
    case ETHERTYPE_IP:
        switch (iph->protocol) //Check the Protocol and do accordingly...
        {       
            case 6:  //TCP Protocol
                print_tcp_packet(packet , size, IPv4);
                break;
            
            case 17: //UDP Protocol
                print_udp_packet(packet , size, IPv4);
                break;
            
            default: //Other protocols
                break;    
        }
        break;
    case ETHERTYPE_IPV6:
        switch (iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt) //Check the Protocol(from next header part) and do accordingly...
        {       
            case 6:  //TCP Protocol
                print_tcp_packet(packet , size, IPv6);
                break;
            
            case 17: //UDP Protocol
                print_udp_packet(packet , size, IPv6);
                break;
            
            default: //Other protocols
                break;    
        }
        break;
    }

    if(showDnsCache) //print content of DNS cache
    {
        printf("\n");
        for (int i = 0; i < cacheSize; i++)
        {
            printf("IP:\t%s \t Hostname: %s\n",ipCacheArray[i],hostnameCacheArray[i]);
        }
    }

    printf("\n###########################################################\n\n");
}

//function for getting informations from TCP packet
void print_tcp_packet(const unsigned char * Buffer, int Size, int IP)
{
    struct sockaddr_in source,dest; 
    struct sockaddr_in6 source6,dest6;

    //ip header part

    unsigned short iphdrlen;
         
    //getting ip header from packet
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    struct ip6_hdr *iph6 = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));

    if (IP == IPv4) iphdrlen = iph->ihl*4;
    else iphdrlen = sizeof(struct ip6_hdr);

    if (IP == IPv4)
    {
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr; //saving source IP adress
        
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr; //saving destination IP adress
    }else
    {
        memset(&source6, 0, sizeof(source6));
        source6.sin6_addr = iph6->ip6_src; //saving source IP adress
        
        memset(&dest6, 0, sizeof(dest6));
        dest6.sin6_addr = iph6->ip6_dst; //saving destination IP adress
    }
    
    //tcp header part

    //getting tcp header from packet
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    //size of header = ethernet header + ip header + TCP header
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    //resolve IP to Hostname if possible and needed
    if (IP == IPv4) resolve(source.sin_addr);
    else resolve6(source6.sin6_addr);

    printf(" : %u ",ntohs(tcph->source)); //source port

    printf("> ");

    //resolve IP to Hostname if possible and needed
    if (IP == IPv4) resolve(dest.sin_addr);
    else resolve6(dest6.sin6_addr);
    
    printf(" : %u",ntohs(tcph->dest)); //destination port
    printf("\n\n");
    cnt = 0;
    PrintData(Buffer,header_size);
    printf("\n");    
    PrintData(Buffer + header_size , Size - header_size );
}

//function for getting informations from UDP packet
void print_udp_packet(const unsigned char *Buffer , int Size, int IP)
{
    struct sockaddr_in source,dest;
    struct sockaddr_in6 source6,dest6;

    //ip header part

    unsigned short iphdrlen;

    //getting ip header from packet         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    struct ip6_hdr *iph6 = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));

    if (IP == IPv4) iphdrlen = iph->ihl*4;
    else iphdrlen = sizeof(struct ip6_hdr);
     
    if (IP == IPv4)
    {
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr; //saving source IP adress
        
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr; //saving destination IP adress
    }else
    {
        memset(&source6, 0, sizeof(source6));
        source6.sin6_addr = iph6->ip6_src; //saving source IP adress
        
        memset(&dest6, 0, sizeof(dest6));
        dest6.sin6_addr = iph6->ip6_dst; //saving destination IP adress
    }

    //udp header part
     
    //getting udp header from packet
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    //size of header = ethernet header + ip header + UDP header
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    //resolve IP to Hostname if possible and needed
    if (IP == IPv4) resolve(source.sin_addr);
    else resolve6(source6.sin6_addr);
    
    printf(" : %u ",ntohs(udph->source)); //source port

    printf("> ");

    //resolve IP to Hostname if possible and needed
    if (IP == IPv4) resolve(dest.sin_addr);
    else resolve6(dest6.sin6_addr);

    printf(" : %u",ntohs(udph->dest)); //destination port
    printf("\n\n");
    cnt = 0;
    PrintData(Buffer , header_size);
    printf("\n");    
    PrintData(Buffer + header_size , Size - header_size);
}

/*********************************************************************************
*
*	Source for function: PrintData
*
*	Title: Packet Sniffer Code in C using sockets | Linux
*	Author: Silver Moon
*	Availability: https://www.binarytides.com/packet-sniffer-code-c-linux/
*
*********************************************************************************/

void PrintData (const unsigned char* data , int Size)
{
    int i,j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("       "); //space between hex and alphabet
            for(j=i-16 ; j<i ; j++)
            {   
                if(j%8==0) printf("  "); //spacing after 8 byt
                if(data[j]>=32 && data[j]<127) printf("%c",(unsigned char)data[j]); //print all printable characters
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("0x%04x  ",cnt); //printing startline counter
        if(i%8==0) printf(" "); // spacing after 8 byt
        printf("%02X ",(unsigned int)data[i]); //printing hex data
        cnt++;
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) printf("   "); //extra missing spaces
             
            printf("       "); //space between hex and alphabet
             
            if(15-i%16>=8) printf(" "); //align
            for(j=i-i%16 ; j<=i ; j++)
            {   
                if(i!=0 && j%8==0) printf("  "); //spacing after 8 byt
                if(data[j]>=32 && data[j]<127) printf("%c",(unsigned char)data[j]); //print all printable characters
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        }
    }
}

//resolve IPv4 to Hostname if possible and needed
void resolve(struct in_addr IPaddr)
{
    char* hostname;
    struct in_addr localIPaddr = IPaddr; //inet_ntoa can overwrite so we copy IPaddr to local variable

    if (!resolveFlag) //dont resolve ip adress
    {
        printf("%s",inet_ntoa(localIPaddr));
    }else //resolving ip adress
    {
        hostname = IPtoHostName(inet_ntoa(localIPaddr)); //trying resolve IPv4
        if (hostname !=0)
        {
            printf("%s",hostname);
        }else //cant resolve IP - printing IP not Hostname
        {
            printf("%s",inet_ntoa(localIPaddr));
        }
    }
}

//resolve IPv6 to Hostname if possible and needed
void resolve6(struct in6_addr IPaddr)
{
    char* hostname;
    struct in6_addr localIPaddr = IPaddr; //inet_ntoa can overwrite so we copy IPaddr to local variable
    char addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6,&localIPaddr,addr,INET6_ADDRSTRLEN);
    
    if (!resolveFlag) //dont resolve ip adress
    {
        printf("%s",addr);
    }else //resolving ip adress
    {
        hostname = IPtoHostName6(addr); //trying resolve IPv6
        if(hostname !=0)
        {
            printf("%s",hostname);
        }else //cant resolve IP - printing IP not Hostname
        {
            printf("%s",addr);
        }
    }
}

/*********************************************************************************
*
*	Base for function: IPtoHostName/IPtoHostName6
*
*	Title: getnameinfo() example problem
*	Author: algorism
*	Availability: https://cboard.cprogramming.com/c-programming/169902-getnameinfo-example-problem.html
*
*********************************************************************************/
//get Hostname for IPv4 from local dns cache/resolved IP
char* IPtoHostName(char* IP)
{
	struct sockaddr_in sa;
	int test;
    int res = 0;

	//preparing structure
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;

    //checking if IPv4 is correct
	test = inet_pton(AF_INET, IP, &sa.sin_addr); 
	if (test != 1) return 0;

    //searching in local DNS cache for resolving IP
    for (int i = 0; i < cacheSize; i++)
    {
        if(strcmp(IP,ipCacheArray[i])==0) //if IP is in cache we return equal hostname
        {
            strcpy(node,hostnameCacheArray[i]);
            return node; //returning hostname from cache
        }
    }
    
    //IP is not in cache - resolving and saving Hostname to cache
    res = getnameinfo((struct sockaddr*) & sa, sizeof(sa),node, sizeof(node), NULL, 0, NI_NAMEREQD);
    
	if (res) 
	{
		return 0;
	}else
	{
        strcpy(ipCacheArray[cachePointer],IP);
        strcpy(hostnameCacheArray[cachePointer],node);

        //moving cachePointer position
        if (cachePointer < cacheSize){
            cachePointer++;
        }else
        {
            cachePointer = 0;
        }
		return node; //returning resolved hostname
	}
}

//get Hostname for IPv6 from local dns cache/resolved IP
char* IPtoHostName6(char* IP)
{
	struct sockaddr_in6 sa6;
	int test;
    int res = 0;

	//preparing structure
	memset(&sa6, 0, sizeof sa6);
	sa6.sin6_family = AF_INET6;

    //checking if IPv6 is correct
	test = inet_pton(AF_INET6, IP, &sa6.sin6_addr); 
    if (test != 1) return 0;
	
    //searching in local DNS cache for resolving IP
    for (int i = 0; i < cacheSize; i++)
    {
        if(strcmp(IP,ipCacheArray[i])==0) //if IP is in cache we return equal hostname
        {
            strcpy(node,hostnameCacheArray[i]);
            return node; //returning hostname from cache
        }
    }
    
    //IP is not in cache - resolving and saving Hostname to cache
    res = getnameinfo((struct sockaddr*) & sa6, sizeof(sa6), node, sizeof(node), NULL, 0, NI_NAMEREQD);

	if (res) 
	{
		return 0;
	}else
	{
        strcpy(ipCacheArray[cachePointer],IP);
        strcpy(hostnameCacheArray[cachePointer],node);

        //moving cachePointer position
        if (cachePointer < cacheSize){
            cachePointer++;
        }else
        {
            cachePointer = 0;
        }
		return node; //returning resolved hostname
	}
}