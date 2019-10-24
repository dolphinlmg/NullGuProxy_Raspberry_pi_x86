#ifndef ETHERNET_H
#define ETHERNET_H

#include <net/ethernet.h>
#include "n_frame.h"

class n_Ethernet : public n_Frame {
public:
    n_Ethernet(uint8_t* data, pcap_pkthdr* header);
    n_Ethernet(const uint8_t* data, pcap_pkthdr* header);
    ether_header* getEthernetHeader() const ;
    uint8_t* getEthDst() const ;
    void setEthDst(uint8_t* dst);
    uint8_t* getEthSrc() const ;
    void setEthSrc(uint8_t* src);
    uint16_t getEthType() const ;
    void setEthType(uint16_t eth_type);
    std::string what() const override { return "Ethernet"; }

private:
    ether_header* ethernet_header;
};

#endif // ETHERNET_H
