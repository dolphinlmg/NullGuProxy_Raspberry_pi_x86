#ifndef N_PCAP_H
#define N_PCAP_H
#include <pcap/pcap.h>
#include <iostream>
#include "Class/Packet/n_tcp.h"

class n_Pcap
{
public:
    n_Pcap(const char* dev);
    ~n_Pcap();
    pcap_t* getHandle() const { return this->handle; } // return handle
    char* getErrorBuf() { return this->errBuf; } 		// return errBuf
    int sendPacket(n_Frame* packet) const ;
    int getNextPacket();
    pcap_pkthdr* getPacketHeader();
    const uint8_t* getPacketData();
    uint32_t getPacketLength();
    n_Frame* recognizePacket();
    int operator>>(n_Frame* &packet);
    int operator<<(n_Frame* &packet);

private:
    pcap_t* handle;
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_pkthdr* header;
    const uint8_t* packet;
};

#endif // N_PCAP_H
