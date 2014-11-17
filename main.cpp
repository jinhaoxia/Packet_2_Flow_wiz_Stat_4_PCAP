#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "u_char_handle.h"
#include "pkt_handler.h"

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

//Global variables
FILE * file;

static pkt_list pl;
static pkt_info_map pim;
static flow_info_map fim;

static u_long pkt_counter = 0;
static u_long buffer_full_times = 0;

const unsigned int ETHER_HEAD_LEN = 14;
const unsigned int UDP_HEAD_LEN = 8;

int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	//command line mode
	if(argc != 2)
	{	
		printf("usage: %s filename", argv[0]);
		return -1;

	}
	
	/* Open the capture file */
	if ((fp = pcap_open_offline(argv[1],			// name of the device
						 errbuf					// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", argv[1]);
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	printf("Reading the file %s...\n", argv[1]);
	pcap_loop(fp, 0, dispatcher_handler, NULL);	
	pcap_close(fp);

	//Handle the data
	printf("Processing...\n");
	pim.handler(pl);
	fim.handler(pim);

	//Write the result.
	printf("Writing the result...\n");
	if(fim.writer(argv[1]) == 1)
		printf("All work done. Exiting...\n");
	else
		printf("Failed to write the result.\n");
	
	return 0;
}



void dispatcher_handler(u_char *temp1, 
						const struct pcap_pkthdr *header, 
						const u_char *pkt_data)
{
	u_int i=0;

	/*
	 * unused variable
	 */
//	(VOID*)temp1;

	/* Capture the packet information */

	u_char	ip_header_len, 
			total_len[2], 
			trans_proto, 
			src_ip[4], 
			dest_ip[4], 
			src_port[2], 
			dest_port[2], 
			trans_header_len;

	u_char broadcast_head[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if( !u_char_equ(broadcast_head, pkt_data, 6) ){ //Is broadcast pkt
		u_char_cpy(&ip_header_len, pkt_data + ETHER_HEAD_LEN, 1);
		//IP header length is counted in 4 bytes.
		ip_header_len &= 0x0f;
		ip_header_len *= 4;
				
		u_char_cpy(total_len, pkt_data + ETHER_HEAD_LEN + 2, 2);

		u_char_cpy(&trans_proto, pkt_data + ETHER_HEAD_LEN + 9, 1);
		switch (trans_proto)
		{
		case 0x06: //TCP
			u_char_cpy(&trans_header_len, pkt_data + ETHER_HEAD_LEN + ip_header_len + 12, 1);
			//The high 4 bits is TCP header length, also counted in 4 bytes. So operate below is a direct way.
			trans_header_len = (trans_header_len & 0xf0) >> 2;
			break;
		
		case 0x11: //UDP
			if (trans_proto == 0x11)
				trans_header_len = UDP_HEAD_LEN;
			break;

		default:
			return;
		}

		u_char_cpy(src_ip, pkt_data + ETHER_HEAD_LEN + 12, 4);
		u_char_cpy(dest_ip, pkt_data + ETHER_HEAD_LEN + 16, 4);
		u_char_cpy(src_port, pkt_data + ETHER_HEAD_LEN + (u_int)ip_header_len, 2);
		u_char_cpy(dest_port, pkt_data + ETHER_HEAD_LEN + (u_int)ip_header_len + 2, 2);

		unsigned int payload_len = ((u_int)total_len[0] << 8) + (u_int)total_len[1] - (u_int)ip_header_len - (u_int)trans_header_len;

		//fprintf(file, "%d.%d.%d.%d, %d, ", src_ip[0], src_ip[1], src_ip[2], src_ip[3], ((u_int)src_port[0] << 8) + (u_int)src_port[1]);
		//fprintf(file, "%d.%d.%d.%d, %d, ", dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3], ((u_int)dest_port[0] << 8) + (u_int)dest_port[1]);
		//fprintf(file, "%ld, %ld, %ld, %ld\n", header->ts.tv_sec, header->ts.tv_usec, header->len, payload_len);

		info_head tih;
		pkt_info tpi;

		tih.src_ip = ((u_long)src_ip[0] << 24) | ((u_long)src_ip[1] << 16) | ((u_long)src_ip[2] << 8) | (u_long)src_ip[3];
		tih.dest_ip = ((u_long)dest_ip[0] << 24) | ((u_long)dest_ip[1] << 16) | ((u_long)dest_ip[2] << 8) | (u_long)dest_ip[3];
		tih.src_port = ((u_short)src_port[0] << 8) | (u_short)src_port[1];
		tih.dest_port = ((u_short)dest_port[0] << 8) | (u_short)dest_port[1];
		//tih.generate_flow_name();
		tih.generate_flow_name_2();

		tpi.sec = header->ts.tv_sec;
		tpi.usec = header->ts.tv_usec;
		tpi.pkt_size = header->len;
		tpi.pld_size = payload_len;
		
		if(pkt_counter <= 1000000){
			pl.append(tih, tpi);
			++ pkt_counter;
		}
		else{
			++ buffer_full_times;
			printf("%ldM packets have already been read. Now buffer is full. Processing...\n", buffer_full_times);
			pim.handler(pl);
			pl.head_to_pkt.clear();
									
			printf("Go on reading...\n");
			pl.append(tih, tpi);
			pkt_counter = 1;
		}

	} //End of if( !u_char_equ(broadcast_head, pkt_data, 6) )
}
