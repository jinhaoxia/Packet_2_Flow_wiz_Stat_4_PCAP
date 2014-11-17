#ifndef INFO_STRUCT
#define INFO_STRUCT

#include <pcap.h>
#include <string>

typedef struct _info_head{
	u_long src_ip;
	u_long dest_ip;
	u_short src_port; 
	u_short dest_port;
	std::string flow_name;

	bool operator<(const struct _info_head & other) const {
	//Must be overloaded as public if this struct is being used as the KEY in STL-map.
		return (this->flow_name < other.flow_name);
	}

	bool operator==(const struct _info_head & other) const{
		//Optional
		return	this->src_ip == other.src_ip && 
				this->dest_ip == other.dest_ip &&
				this->src_port == other.src_port &&
				this->dest_port == other.dest_port;
	}

	void generate_flow_name(){
		//For use flowname in the filename
		char name[50];
		sprintf(name, "%ld.%ld.%ld.%ld_%ld - %ld.%ld.%ld.%ld_%ld",
			(this->src_ip & 0xff000000) >> 24,
			(this->src_ip & 0x00ff0000) >> 16,
			(this->src_ip & 0x0000ff00) >> 8,
			this->src_ip & 0x000000ff,
			this->src_port,
			(this->dest_ip & 0xff000000) >> 24,
			(this->dest_ip & 0x00ff0000) >> 16,
			(this->dest_ip & 0x0000ff00) >> 8,
			this->dest_ip & 0x000000ff,
			this->dest_port);
		this->flow_name.assign(name);
	}

	void generate_flow_name_2(){
		//For actually use.
		char name[50];
		sprintf(name, "%ld.%ld.%ld.%ld:%ld - %ld.%ld.%ld.%ld:%ld",
			(this->src_ip & 0xff000000) >> 24,
			(this->src_ip & 0x00ff0000) >> 16,
			(this->src_ip & 0x0000ff00) >> 8,
			this->src_ip & 0x000000ff,
			this->src_port,
			(this->dest_ip & 0xff000000) >> 24,
			(this->dest_ip & 0x00ff0000) >> 16,
			(this->dest_ip & 0x0000ff00) >> 8,
			this->dest_ip & 0x000000ff,
			this->dest_port);
		this->flow_name.assign(name);
	}

	struct _info_head reversed_info_head() const{
		info_head rih;

		rih.dest_ip = this->src_ip;
		rih.src_ip = this->dest_ip;
		rih.dest_port = this->src_port;
		rih.src_port = this->dest_port;
		rih.generate_flow_name();

		return rih;
	}
} info_head;

typedef struct _pkt_info{
	u_long sec;
	u_long usec;
	u_int pkt_size;
	u_int pld_size;
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

} flow_info;

typedef struct _pkt{
	info_head head;
	pkt_info info;
} pkt;

typedef struct _uni_dir_flow{
	flow_info A;
	flow_info B;
} uni_dir_flow;

#endif