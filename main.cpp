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

	//Generate proper file name
	//char str_time[30];
	//struct tm *p_time;
	//time_t t_temp = time(NULL);
	//p_time = localtime(&t_temp);

	//sprintf(str_time, "%4d-%2d-%2d-%2d-%2d-%2d", 
	//	p_time->tm_year + 1900,
	//	p_time->tm_mon + 1,
	//	p_time->tm_mday,
	//	p_time->tm_hour,
	//	p_time->tm_min,
	//	p_time->tm_sec);

	//char resname[150];
	//strcpy(resname, argv[1]);
	//strcat(resname, "-");
	//strcat(resname, str_time);
	//strcat(resname, ".txt");
	//
	//file = fopen(resname, "w");

	/* read and dispatch packets until EOF is reached */
	pcap_loop(fp, 0, dispatcher_handler, NULL);


	pcap_close(fp);

	pim.handler(pl);
	//pim.writer(argv[1]);
	fim.handler(pim);
	fim.writer(argv[1]);

	//fclose(file);

	return 0;
}



void dispatcher_handler(u_char *temp1, 
						const struct pcap_pkthdr *header, 
						const u_char *pkt_data)
{
	u_int i=0;

	const unsigned int ETHER_HEAD_LEN = 14;
	const unsigned int UDP_HEAD_LEN = 8;
	
	/*
	 * unused variable
	 */
//	(VOID*)temp1;

	/* print packet information */

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
		tih.src_port = ((u_int)src_port[0] << 8) | (u_int)src_port[1];
		tih.dest_port = ((u_int)dest_port[0] << 8) | (u_int)dest_port[1];
		//tih.generate_flow_name();
		tih.generate_flow_name_2();

		tpi.sec = header->ts.tv_sec;
		tpi.usec = header->ts.tv_usec;
		tpi.pkt_size = header->len;
		tpi.pld_size = payload_len;
		
		pl.append(tih, tpi);

	} //End of 	if( !u_char_equ(broadcast_head, pkt_data, 6) )
}
