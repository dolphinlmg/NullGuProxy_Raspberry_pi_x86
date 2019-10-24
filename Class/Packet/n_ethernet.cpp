#include "n_ethernet.h"

// constructor with uint8_t*
n_Ethernet::n_Ethernet(uint8_t* data, pcap_pkthdr* header) : n_Frame(data, header) {
    this->ethernet_header = reinterpret_cast<ether_header*>(this->getFrameData());
}

// constructor with const uint8_t*
n_Ethernet::n_Ethernet(const uint8_t* data, pcap_pkthdr* header) : n_Frame(data, header) {
    this->ethernet_header = reinterpret_cast<ether_header*>(this->getFrameData());
}

// return ether_header
ether_header* n_Ethernet::getEthernetHeader() const {
    return this->ethernet_header;
}

// return dest mac addr to uint8_t*
uint8_t* n_Ethernet::getEthDst() const {
    return this->ethernet_header->ether_dhost;
}

// set mac addr by uint8_t*
void n_Ethernet::setEthDst(uint8_t* dst){
    memcpy(this->ethernet_header->ether_dhost, dst, 6);
}

// return source mac addr to uint8_t*
uint8_t* n_Ethernet::getEthSrc() const {
    return this->ethernet_header->ether_shost;
}

// set mac addr by uint8_t*
void n_Ethernet::setEthSrc(uint8_t* src){
    memcpy(this->ethernet_header->ether_shost, src, 6);
}

// return ether_type to uint16_t
uint16_t n_Ethernet::getEthType() const {
    return this->ethernet_header->ether_type;
}

// set ether_type by uint16_t
void n_Ethernet::setEthType(uint16_t eth_type){
    this->ethernet_header->ether_type = eth_type;
}

