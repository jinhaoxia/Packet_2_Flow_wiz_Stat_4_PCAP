#ifndef STAT_CAL
#define STAT_CAL

#include "info_struct.h"
#include <list>
#include <vector>
#include <cmath>

u_long u_long_max();

const u_long U_LONG_MAX = u_long_max();
const u_long U_LONG_MIN = 0L;

u_long u_long_max(){
	u_long max = 0xff;
	for(int i = 1; i < sizeof(u_long); ++i){
		max <<= 8;
		max &= 0xff;		
	}
	return max;
}
using namespace std;

u_long count_cal(const vector<u_long> &);
u_long total_cal(const vector<u_long> &);

u_long max_cal(const vector<u_long> &);
u_long min_cal(const vector<u_long> &);
double mean_cal(const vector<u_long> &);
double stde_cal(const vector<u_long> &, const flow_info &);
double skew_cal(const vector<u_long> &, const flow_info &);
double kurt_cal(const vector<u_long> &, const flow_info &);

flow_info stat_cal(const vector<pkt_info> & p){
	typedef vector<pkt_info>::const_iterator pkt_info_it;
	pkt_info_it pii = p.begin(), pii_p = p.begin();
	
	//Split into three vectors
	vector<u_long> tim_intv, pkt_size, pld_size;
	u_long intv = 0L;

	tim_intv.push_back(intv);
	pkt_size.push_back(pii->pkt_size);
	pld_size.push_back(pii->pld_size);
	
	//Fill the three vectors
	for(++ pii; pii != p.end(); ++ pii, ++ pii_p){
		intv = (pii->sec - pii_p->sec) * 100000;
		intv += pii->usec;
		intv -= pii_p->usec;
		tim_intv.push_back(intv);

		pkt_size.push_back(pii->pkt_size);
		pld_size.push_back(pii->pld_size);
	}
		
	flow_info cur_flow_info;

	//Fill the cur_flow_info
	cur_flow_info.total_pkt_count = count_cal(pkt_size);

	cur_flow_info.total_pkt_size = total_cal(pkt_size);
	cur_flow_info.total_pld_size = total_cal(pld_size);

	cur_flow_info.max_pkt_size = max_cal(pkt_size);
	cur_flow_info.max_pld_size = max_cal(pld_size);
	cur_flow_info.max_tim_intv = max_cal(tim_intv);

	cur_flow_info.min_pkt_size = min_cal(pkt_size);
	cur_flow_info.min_pld_size = min_cal(pld_size);
	cur_flow_info.min_tim_intv = min_cal(tim_intv);

	cur_flow_info.mean_pkt_size = mean_cal(pkt_size);
	cur_flow_info.mean_pld_size = mean_cal(pld_size);
	cur_flow_info.mean_tim_intv = mean_cal(tim_intv);

	//Members below have dependecy on members above. Do NOT re-order this part.
	cur_flow_info.stde_pkt_size = stde_cal(pkt_size, cur_flow_info);
	cur_flow_info.stde_pld_size = stde_cal(pld_size, cur_flow_info);
	cur_flow_info.stde_tim_intv = stde_cal(tim_intv, cur_flow_info);

	cur_flow_info.skew_pkt_size = skew_cal(pkt_size, cur_flow_info);
	cur_flow_info.skew_pld_size = skew_cal(pld_size, cur_flow_info);
	cur_flow_info.skew_tim_intv = skew_cal(tim_intv, cur_flow_info);

	cur_flow_info.skew_pkt_size = skew_cal(pkt_size, cur_flow_info);
	cur_flow_info.skew_pld_size = skew_cal(pld_size, cur_flow_info);
	cur_flow_info.skew_tim_intv = skew_cal(tim_intv, cur_flow_info);
	
	return cur_flow_info;
}

u_long count_cal(const vector<u_long> & v){
	vector<u_long>::const_iterator it = v.begin();

	u_long total = U_LONG_MIN;
	for(; it != v.end(); ++ it)
		++ total;
	return total;
}

u_long total_cal(const vector<u_long> & v){
	vector<u_long>::const_iterator it = v.begin();

	u_long total = U_LONG_MIN;
	for(; it != v.end(); ++ it)
		total += (double)(*it);
	return total;
}

u_long max_cal (const vector<u_long> & v){
	vector<u_long>::const_iterator it = v.begin();
	
	u_long max = U_LONG_MIN;
	for(; it != v.end(); ++ it){
		if(max < *it)
			max = *it;
	}
	return max;
}

u_long min_cal (const vector<u_long> & v){
	vector<u_long>::const_iterator it = v.begin();
	
	u_long min = U_LONG_MAX;
	for(; it != v.end(); ++ it){
		if(min > *it)
			min = *it;
	}
	return min;
}

double mean_cal(const vector<u_long> & v){
	vector<u_long>::const_iterator it = v.begin();

	double mean = 0;
	for(u_int i = 0; it != v.end(); ++ it, ++i)
		mean = mean * ( i / (i + 1) ) + (double)(*it) * ( 1 / (i + 1) );
	return mean;
}

double stde_cal(const vector<u_long> & v, const flow_info & f){
	vector<u_long>::const_iterator it = v.begin();

	return 0;
}

double skew_cal(const vector<u_long> & v, const flow_info & f){
	vector<u_long>::const_iterator it = v.begin();

	return 0;
}

double kurt_cal(const vector<u_long> & v, const flow_info & f){
	vector<u_long>::const_iterator it = v.begin();

	return 0;
}

#endif