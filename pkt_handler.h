#include "info_struct.h"
#include "stat_cal.h"

#include <map>
#include <vector>

#include <time.h>
#include <stdlib.h>

#ifndef PKT_HANDLER
#define PKT_HANDLER

using namespace std;

class pkt_list{ 
	//Packet List.
	//Raw packets information.
public:
	vector<pkt> head_to_pkt;

public:
	int append(const info_head & head, const pkt_info & info){
		pkt tmp;
		tmp.head = head;
		tmp.info = info;
	
		head_to_pkt.push_back(tmp);

		return 1;
	}
};

class pkt_info_map{ 
	//Packet information map.
	//Read information from packet list, transfer the packets into flows.
public:
	map<info_head, vector<pkt_info> > head_to_pkts;

public:
	int handler(const pkt_list & p){
		//Core handling module. DO NOT modify!
		typedef vector<pkt>::const_iterator pkt_it;
		typedef map<info_head, vector<pkt_info> >::iterator map_it;

		pkt_it pi = p.head_to_pkt.begin();

		for(; pi != p.head_to_pkt.end(); ++ pi){
			map_it mi = head_to_pkts.find(pi->head);
			if (mi == head_to_pkts.end() ){
				vector<pkt_info> temp_vec;
				temp_vec.push_back(pi->info);

				head_to_pkts.insert(make_pair(pi->head, temp_vec) );
			}
			else
				mi->second.push_back(pi->info);
		}

		return 1;
	}

	int writer(const char * pcap_file_name){
		//This method is for testing purpose only.
		typedef vector<pkt_info>::const_iterator pkt_info_it;
		typedef map<info_head, vector<pkt_info> >::iterator map_it;

		map_it mi = head_to_pkts.begin();
		
		FILE * fp;
		char filename[200];

		for(; mi != head_to_pkts.end(); ++ mi){
			
			pkt_info_it pii = mi->second.begin(), pii_p = mi->second.begin();

			//Create and fill the new vector: time interval.
			vector<u_long> tim_intv;
			u_long intv = 0L;
			tim_intv.push_back(intv);
			for(++ pii; pii != mi->second.end(); ++ pii, ++ pii_p){
				intv = (pii->sec - pii_p->sec) * 1000000;
				intv += pii->usec;
				intv -= pii_p->usec;
				tim_intv.push_back(intv);
			}

			//Create file name
			char str_time[20];
			struct tm *p_time;
			time_t t_temp = time(NULL);
			p_time = localtime(&t_temp);

			sprintf(str_time, "%4d-%2d-%2d-%2d-%2d-%2d", 
				p_time->tm_year + 1900,
				p_time->tm_mon + 1,
				p_time->tm_mday,
				p_time->tm_hour,
				p_time->tm_min,
				p_time->tm_sec);

			strcpy(filename, pcap_file_name);
			strcat(filename, " - ");
			strcat(filename, str_time);
			strcat(filename, " - ");
			strcat(filename, mi->first.flow_name.c_str());
			strcat(filename, ".txt");

			//Write the file
			fp = fopen(filename, "w");
			pii = mi->second.begin();
			vector<u_long>::const_iterator uli = tim_intv.begin();
			for(; pii != mi->second.end() || uli != tim_intv.end(); ++ pii, ++uli){
				fprintf(fp, "%ld, %ld, %ld\n", *uli, pii->pkt_size, pii->pld_size);
			}
			fclose(fp);
		}

		return 1;
	}
};

class flow_info_map{ 
	//Flow information map
	//Read information from packet information map, extract the statistics from each flow.
public:
	map <info_head, flow_info> head_to_flow;

public:
	int handler(const pkt_info_map & p){
		typedef map<info_head, vector<pkt_info> >::const_iterator pkt_map_it;
		typedef map<info_head, flow_info>::iterator flow_map_it;
		
		flow_info fi;
		pkt_map_it pmi = p.head_to_pkts.begin();
		for(; pmi != p.head_to_pkts.end(); ++ pmi)		
			if ( stat_cal(pmi->second, &fi) )
				head_to_flow.insert(make_pair(pmi->first, fi) );

		return 1;
	}

	int writer(const char * pcap_file_name){
		//This method is for use actually.

		
		//Create filename
		char str_time[20];
		struct tm *p_time;
		time_t t_temp = time(NULL);
		p_time = localtime(&t_temp);

		sprintf(str_time, "%4d-%2d-%2d-%2d-%2d-%2d", 
			p_time->tm_year + 1900,
			p_time->tm_mon + 1,
			p_time->tm_mday,
			p_time->tm_hour,
			p_time->tm_min,
			p_time->tm_sec);

		char filename[200];
		strcpy(filename, pcap_file_name);
		strcat(filename, " - ");
		strcat(filename, str_time);
		strcat(filename, ".csv");	

		//Open the file
		FILE * fp = fopen(filename, "w");
		if(fp == NULL) return 0;

		//Travarse the map head_to_flow and write file
		typedef map<info_head, flow_info>::iterator flow_map_it;
		flow_map_it fmi = head_to_flow.begin();
		
		//Print the title row.
		fprintf(fp, "src_ip : src_port - dest_ip : dest_port, \
u_long total_pkt_size, u_long total_pld_size, u_long total_pkt_count, \
\
u_long max_pkt_size, u_long min_pkt_size, double mean_pkt_size, \
double stde_pkt_size, double skew_pkt_size, double kurt_pkt_size, \
\
u_long max_pld_size, u_long min_pld_size, double mean_pld_size, \
double stde_pld_size, double skew_pld_size, double kurt_pld_size, \
\
u_long max_tim_intv, u_long min_tim_intv, double mean_tim_intv, \
double stde_tim_intv, double skew_tim_intv, double kurt_tim_intv\n");

		//Print the data row.
		for (; fmi != head_to_flow.end(); ++ fmi){
			if ( fprintf(fp, "%s, %ld, %ld, %ld, \
%ld, %ld, %lf, %lf, %lf, %lf, \
%ld, %ld, %lf, %lf, %lf, %lf, \
%ld, %ld, %lf, %lf, %lf, %lf\n", 
			fmi->first.flow_name.c_str(), 
			fmi->second.total_pkt_size, fmi->second.total_pld_size, fmi->second.total_pkt_count,

			fmi->second.max_pkt_size, fmi->second.min_pkt_size, fmi->second.mean_pkt_size,
			fmi->second.stde_pkt_size, fmi->second.skew_pkt_size, fmi->second.kurt_pkt_size,
			
			fmi->second.max_pld_size, fmi->second.min_pld_size, fmi->second.mean_pld_size,
			fmi->second.stde_pld_size, fmi->second.skew_pld_size, fmi->second.kurt_pld_size,
			
			fmi->second.max_tim_intv, fmi->second.min_tim_intv, fmi->second.mean_tim_intv,
			fmi->second.stde_tim_intv, fmi->second.skew_tim_intv, fmi->second.kurt_tim_intv) == EOF ){

				fclose(fp);
				return 0;
			}//End of if
		}//End of for (; fmi != head_to_flow.end(); ++ fmi)
		
		//End-ups
		fclose(fp);
		return 1;
	}
};

class uni_dir_flow_list{ 
	//Unidirectional flow information list. 
	//Not in use.
public:
	map<info_head, uni_dir_flow> head_to_uni_dir_flow;

public:
	int handler(const flow_info_map & f){
		typedef map<info_head, flow_info>::const_iterator flow_map_it;
		typedef map<info_head, uni_dir_flow>::iterator uni_dir_flow_it;

		flow_map_it fmi = f.head_to_flow.begin();

		for(; fmi != f.head_to_flow.end(); ++fmi){
			uni_dir_flow_it udfi_1 = head_to_uni_dir_flow.find(fmi->first);
			uni_dir_flow_it udfi_2 = head_to_uni_dir_flow.find(fmi->first.reversed_info_head());

			if( udfi_1 == head_to_uni_dir_flow.end() &&
				udfi_1 == head_to_uni_dir_flow.end() ){
				uni_dir_flow temp;
				temp.A = fmi->second;
				head_to_uni_dir_flow.insert(make_pair(fmi->first, temp));
			}
		}

		return 1;
	}
};

#endif