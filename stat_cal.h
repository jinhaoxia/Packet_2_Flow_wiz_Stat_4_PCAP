#ifndef STAT_CAL
#define STAT_CAL

#include "info_struct.h"
#include <list>

using namespace std;

flow_info stat_cal(const list<pkt_info> & p){
	typedef list<pkt_info>::const_iterator pkt_info_it;
	pkt_info_it pii = p.begin();
	flow_info cur_flow_info;
	//20141113

	return cur_flow_info;
}

#endif