#ifndef N_PCAP_DATA_H
#define N_PCAP_DATA_H
#include <pcap/pcap.h>
#include <vector>
#include <fstream>
#include <iostream>

#include "Class/Packet/n_tcp.h"

/*
struct pcap_file_header {
    bpf_u_int32 magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;	     // gmt to local correction
    bpf_u_int32 sigfigs;	 // accuracy of timestamps
    bpf_u_int32 snaplen;	 // max length saved portion of each pkt
    bpf_u_int32 linktype;	 // data link type (LINKTYPE_*)
};
*/


typedef struct n_pcap_file_packet_header {
  uint32_t ts_sec;         // timestamp seconds
  uint32_t ts_usec;        // timestamp microseconds
  uint32_t incl_len;       // number of octets of packet saved in file
  uint32_t orig_len;       // actual length of packet
} n_pcap_fpkthdr;


class n_Pcap_Data
{
public:
    n_Pcap_Data(const char* fileName);
    ~n_Pcap_Data();
    bool push_packet(n_Frame* packet);
    void exportToFile();
    bool operator<<(n_Frame* &packet);

private:
    const char* fileName;
    pcap_file_header* fileHeader;
    std::vector<n_pcap_fpkthdr*> packetHeader;
    std::vector<n_Frame*> packetList;
    std::ofstream os;
};

#endif // N_PCAP_DATA_H
