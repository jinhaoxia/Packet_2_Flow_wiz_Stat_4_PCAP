#ifndef STAT_CAL
#define STAT_CAL

#include "info_struct.h"
#include <list>
#include <vector>
#include <cmath>

u_long u_long_max();

const u_long U_LONG_MAX = u_long_max();
const u_long U_LONG_MIN = 0L;
const u_long SEC_TO_uSEC = 1000000L;

const int VALID_FLOW_THRES = 10;

const double EPSILON = 0.00001f;

u_long u_long_max(){
	u_long max = 0x7f;
	for(int i = 1; i < sizeof(u_long); ++i){
		max <<= 8;
		max |= 0xff;	
	}
	return max;
}

using namespace std;

u_long count_cal(const vector<u_long> &);
u_long total_cal(const vector<u_long> &);

u_long max_cal(const vector<u_long> &);
u_long min_cal(const vector<u_long> &);
double mean_cal(const vector<u_long> &);
double stde_cal(const vector<u_long> &, const double &, const double &);
double skew_cal(const vector<u_long> &, const double &, const double &);
double kurt_cal(const vector<u_long> &, const double &, const double &, const double &);

bool stat_cal(const vector<pkt_info> & p, flow_info * p_fi){
	if(p_fi == NULL) return false;

	typedef vector<pkt_info>::const_iterator pkt_info_it;
	pkt_info_it pii = p.begin(), pii_p = p.begin();

	//Split into three vectors
	vector<u_long> tim_intv, pkt_size, pld_size;
	u_long intv = 0L;

	//tim_intv.push_back(intv);
	//It should be highly noticed here that if there are n packets in a flow,
	//then there will be (n - 1) time intervals for this flow.
	pkt_size.push_back(pii->pkt_size);
	pld_size.push_back(pii->pld_size);	

	//Fill the three vectors
	for(++ pii; pii != p.end(); ++ pii, ++ pii_p){
		intv = (pii->sec - pii_p->sec) * SEC_TO_uSEC;
		intv += pii->usec;
		intv -= pii_p->usec;
		tim_intv.push_back(intv);

		pkt_size.push_back(pii->pkt_size);
		pld_size.push_back(pii->pld_size);
	}		

	//Fill the *p_fi
	p_fi->total_pkt_count = (u_long)pkt_size.size();
	if( p_fi->total_pkt_count < VALID_FLOW_THRES ) return false;

	p_fi->total_pkt_size = total_cal(pkt_size);
	p_fi->total_pld_size = total_cal(pld_size);

	p_fi->max_pkt_size = max_cal(pkt_size);
	p_fi->max_pld_size = max_cal(pld_size);
	p_fi->max_tim_intv = max_cal(tim_intv);

	p_fi->min_pkt_size = min_cal(pkt_size);
	p_fi->min_pld_size = min_cal(pld_size);
	p_fi->min_tim_intv = min_cal(tim_intv);

	p_fi->mean_pkt_size = mean_cal(pkt_size);
	p_fi->mean_pld_size = mean_cal(pld_size);
	p_fi->mean_tim_intv = mean_cal(tim_intv);

	//Members below have dependecy on members above. Do NOT re-order this part.
	p_fi->stde_pkt_size = stde_cal( pkt_size, p_fi->mean_pkt_size, (p_fi->max_pkt_size - p_fi->min_pkt_size) );
	p_fi->stde_pld_size = stde_cal( pld_size, p_fi->mean_pld_size, (p_fi->max_pld_size - p_fi->min_pld_size) );
	p_fi->stde_tim_intv = stde_cal( tim_intv, p_fi->mean_tim_intv, (p_fi->max_tim_intv - p_fi->min_tim_intv) );

	p_fi->skew_pkt_size = skew_cal(pkt_size, p_fi->mean_pkt_size, p_fi->stde_pkt_size);
	p_fi->skew_pld_size = skew_cal(pld_size, p_fi->mean_pld_size, p_fi->stde_pld_size);
	p_fi->skew_tim_intv = skew_cal(tim_intv, p_fi->mean_tim_intv, p_fi->stde_tim_intv);

	p_fi->kurt_pkt_size = kurt_cal(pkt_size, p_fi->mean_pkt_size, p_fi->stde_pkt_size, p_fi->skew_pkt_size);
	p_fi->kurt_pld_size = kurt_cal(pld_size, p_fi->mean_pld_size, p_fi->stde_pld_size, p_fi->skew_pld_size);
	p_fi->kurt_tim_intv = kurt_cal(tim_intv, p_fi->mean_tim_intv, p_fi->stde_tim_intv, p_fi->skew_tim_intv);
	
	return true;
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
		total += *it;
	return total;
}

u_long max_cal (const vector<u_long> & v){
	vector<u_long>::const_iterator it = v.begin();
	
	u_long max = U_LONG_MIN;
	for(; it != v.end(); ++ it)
		if(max < *it) max = *it;

	return max;
}

u_long min_cal (const vector<u_long> & v){
	vector<u_long>::const_iterator it = v.begin();
	
	u_long min = U_LONG_MAX;
	for(; it != v.end(); ++ it)
		if(min > *it) min = *it;

	return min;
}

double mean_cal(const vector<u_long> & v){
	vector<u_long>::const_iterator it = v.begin();

	double mean = 0.0f;
	for(u_int i = 0; it != v.end(); ++ it, ++ i)
		mean = mean * ( (double)i / (double)(i + 1) ) + (double)(*it) * ( (double)1 / (double)(i + 1) );

	return mean;
}

double stde_cal(const vector<u_long> & v, 
				const double & mean, 
				const double & diff_max_min){
	//STandard DEviation is sqrt of variance. Defined below
	//STDE = sqrt( MEAN(X^2) - MEAN(X) )

	//Due to there is no negative in v, so if the mean equals 0.0f, the numbers in v is all 0.
	if ( mean < EPSILON || diff_max_min < EPSILON ) return 0.0f;

	vector<u_long>::const_iterator it = v.begin();
	
	double x_2_mean = 0, x_2 = 0;
	for(u_int i = 0; it != v.end(); ++ it, ++ i){
		x_2 = pow((double)(*it), 2);;
		x_2_mean = x_2_mean * ( (double) i / (double)(i + 1) ) + x_2 * ( (double)1 / (double)(i + 1) );
	}
	return sqrt( x_2_mean - mean * mean );
}

double skew_cal(const vector<u_long> & v, 
				const double & mean, 
				const double & stde){
	//SKEWness is defined below
	//SKEW = ( MEAN(X^3) - 3 * STDE(X)^2 * MEAN(X) - MEAN(X)^3 ) / STDE(X)^3

	//Due to there is no negative in v, so if the mean equals 0.0f, the numbers in v is all 0.
	//If the stde is 0, then the skewness is meaningless because of the devided by 0 error.
	if ( mean < EPSILON || stde < EPSILON ) return 0.0f;

	vector<u_long>::const_iterator it = v.begin();
	
	double x_3_mean = 0, x_3;
	for(u_int i = 0; it != v.end(); ++ it, ++i){
		x_3 = pow((double)(*it), 3);
		x_3_mean = x_3_mean * ( (double) i / (double)(i + 1) ) + x_3 * ( (double)1 / (double)(i + 1) );
	}

	return ( x_3_mean - 3 * pow(stde, 2) * mean - pow(mean, 3) ) / pow(stde, 3);
}

double kurt_cal(const vector<u_long> & v, 
				const double & mean, 
				const double & stde, 
				const double & skew){
	//KURTosis is defined below
	//KURT = ( E(X^4) - 4 * SKEW(X) * STDE(X)^3 * MEAN(X) - 6 * STDE(X)^2 * MEAN(X)^2 - MEAN(X)^4 ) / STDE(X)^4

	//Due to there is no negative in v, so if the mean equals 0.0f, the numbers in v is all 0.
	//If the stde is 0, then the skewness is meaningless because of the devided by 0 error.
	if ( mean < EPSILON || stde < EPSILON ) return 0.0f;

	vector<u_long>::const_iterator it = v.begin();
	
	double x_4_mean = 0 ,x_4 = 0;
	for(u_int i = 0; it != v.end(); ++ it, ++i){
		x_4 = pow((double)(*it), 4);
		x_4_mean = x_4_mean * ( (double) i / (double)(i + 1) ) + x_4 * ( (double)1 / (double)(i + 1) );
	}

	return ( x_4_mean - 4 * skew * pow(stde, 3) * mean - 6 * pow(stde, 2) * pow(mean, 2) - pow(mean, 4) ) / pow(stde ,4);
}

#endif