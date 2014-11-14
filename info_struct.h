#include <pcap.h>

#ifndef INFO_STRUCT
#define INFO_STRUCT

typedef struct _info_head{
	u_int src_ip;
	u_int dest_ip;
	u_int src_port; 
	u_int dest_port;

	bool operator<(const struct _info_head & other) const {
	//Must be overloaded as public if this struct is being used as the KEY in STL-map.
		if (this->src_ip < other.src_ip) return true;
		if (this->dest_ip < other.dest_ip) return true;
		if (this->src_port < other.src_port) return true;
		if (this->dest_port < other.dest_port) return true;
		return false;
	}

	bool operator==(const struct _info_head & other) const{
		//Optional
		return	this->src_ip == other.src_ip && 
				this->dest_ip == other.dest_ip &&
				this->src_port == other.src_port &&
				this->dest_port == other.dest_port;
	}
} info_head;

typedef struct _pkt_info{
	u_long sec;
	u_long usec;
	u_long pkt_size;
	u_long pld_size;
} pkt_info;

typedef struct _flow_info{
	u_long total_pkt_size;
	u_long total_pld_size;
	u_long total_pkt_count;

	u_long max_pkt_size;
	u_long min_pkt_size;
	double mean_pkt_size;
	double stde_pkt_size;
	double skew_pkt_size;
	double kurt_pkt_size;

	u_long max_pld_size;
	u_long min_pld_size;
	double mean_pld_size;
	double stde_pld_size;
	double skew_pld_size;
	double kurt_pld_size;

	u_long max_tim_intv;
	u_long min_tim_intv;
	double mean_tim_intv;
	double stde_tim_intv;
	double skew_tim_intv;
	double kurt_tim_intv;

//	struct _flow_info(const list<pkt_info> &);
} flow_info;

typedef struct _pkt{
	info_head head;
	pkt_info info;
} pkt;

typedef struct _uni_dir_flow{
	flow_info A;
	flow_info B;
} uni_dir_flow;

info_head reversed_info_head(const info_head & ih){
	info_head rih;

	rih.dest_ip = ih.src_ip;
	rih.src_ip = ih.dest_ip;

	rih.dest_port = ih.src_port;
	rih.src_port = ih.dest_port;

	return rih;
}

#endif