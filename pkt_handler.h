#include "info_struct.h"
#include "stat_cal.h"
#include <map>
#include <list>

#ifndef PKT_HANDLER
#define PKT_HANDLER

using namespace std;

class pkt_list{
public:
	static list<pkt> head_to_pkt;

public:
	static int append(const info_head & head, const pkt_info & info){
		pkt tmp;
		tmp.head = head;
		tmp.info = info;
	
		head_to_pkt.push_back(tmp);

		return 1;
	}
};

class pkt_info_map{
public:
	static map<info_head, list<pkt_info> > head_to_pkts;

public:
	static int handler(const pkt_list & p){
		typedef map<info_head, list<pkt_info> >::iterator map_it;
		typedef list<pkt_info>::iterator pkt_info_it;
		typedef list<pkt>::iterator pkt_it;

		pkt_it pi = p.head_to_pkt.begin();

		for(; pi != p.head_to_pkt.end(); ++ pi){
			map_it mi = head_to_pkts.find(pi->head);
			if (mi == head_to_pkts.end() ){
				list<pkt_info> temp_list;
				temp_list.push_back(pi->info);

				head_to_pkts.insert(make_pair(pi->head, temp_list) );
			}
			else
				mi->second.push_back(pi->info);
		}

		return 1;
	}
};

class flow_info_map{
public:
	static map <info_head, flow_info> head_to_flow;

public:
	static int handler(const pkt_info_map & p){
		typedef map<info_head, list<pkt_info> >::iterator pkt_map_it;
		typedef list<pkt_info>::iterator pkt_info_it;
		typedef map<info_head, flow_info>::iterator flow_map_it;
		
		pkt_map_it pmi = p.head_to_pkts.begin();

		for(; pmi != p.head_to_pkts.end(); ++ pmi){
			flow_info fi = stat_cal(pmi->second);
			head_to_flow.insert(make_pair(pmi->first, fi) );
		}	

		return 1;
	}
};

class uni_dir_flow_list{
public:
	static map<info_head, uni_dir_flow> head_to_uni_dir_flow;

public:
	static int handler(const flow_info_map & f){
		typedef map<info_head, flow_info>::iterator flow_map_it;
		typedef map<info_head, uni_dir_flow>::iterator uni_dir_flow_it;

		flow_map_it fmi = f.head_to_flow.begin();

		for(; fmi != f.head_to_flow.end(); ++fmi){
			uni_dir_flow_it udfi_1 = head_to_uni_dir_flow.find(fmi->first);
			uni_dir_flow_it udfi_2 = head_to_uni_dir_flow.find(reversed_info_head(fmi->first));

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