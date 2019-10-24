#include "n_ip.h"

// constructor with uint8_t*
n_IP::n_IP(uint8_t* data, pcap_pkthdr* header) : n_Ethernet (data, header){
    this->ip_header = reinterpret_cast<iphdr*>(this->getFrameData() + sizeof(ether_header));
}

// constructor with const uint8_t*
n_IP::n_IP(const uint8_t* data, pcap_pkthdr* header) : n_Ethernet (data, header){
    this->ip_header = reinterpret_cast<iphdr*>(this->getFrameData() + sizeof(ether_header));
}

// return iphdr*
iphdr* n_IP::getIPData() const {
    return this->ip_header;
}

// return dest ip addr
uint32_t n_IP::getIPDst() const {
    return this->ip_header->daddr;
}

// set dest ip addr
void n_IP::setIPDst(uint32_t addr){
    this->ip_header->daddr = addr;
}

// return source ip addr
uint32_t n_IP::getIPSrc() const {
    return this->ip_header->saddr;
}

// set source ip addr
void n_IP::setIPSrc(uint32_t addr){
    this->ip_header->saddr = addr;
}

// return protocol number of ip header
uint8_t n_IP::getProtocol() const {
    return this->ip_header->protocol;
}

// set protocol number of ip header
uint32_t n_IP::getSizeOfIPHeader() const {
    return (this->ip_header->ihl & 0xf) * 4;
}

/* function: ip_checksum_add
 * adds data to a checksum. only known to work on little-endian hosts
 * current - the current checksum (or 0 to start a new checksum)
 *   data        - the data to add to the checksum
 *   len         - length of data
 */
uint32_t ip_checksum_add(uint32_t current, const void* data, int len) {
    uint32_t checksum = current;
    int left = len;
    const uint16_t* data_16 = reinterpret_cast<const uint16_t*>(data);
    while (left > 1) {
        checksum += *data_16;
        data_16++;
        left -= 2;
    }
    if (left) {
        checksum += *reinterpret_cast<const uint8_t*>(data_16);
    }
    return checksum;
}
/* function: ip_checksum_fold
 * folds a 32-bit partial checksum into 16 bits
 *   temp_sum - sum from ip_checksum_add
 *   returns: the folded checksum in network byte order
 */
uint16_t ip_checksum_fold(uint32_t temp_sum) {
    while (temp_sum > 0xffff) {
        temp_sum = (temp_sum >> 16) + (temp_sum & 0xFFFF);
    }
    return static_cast<uint16_t>(temp_sum);
}
/* function: ip_checksum_finish
 * folds and closes the checksum
 *   temp_sum - sum from ip_checksum_add
 *   returns: a header checksum value in network byte order
 */
uint16_t ip_checksum_finish(uint32_t temp_sum) {
    return ~ip_checksum_fold(temp_sum);
}
/* function: ip_checksum
 * combined ip_checksum_add and ip_checksum_finish
 *   data - data to checksum
 *   len  - length of data
 */
uint16_t ip_checksum(const void* data, int len) {
    // TODO: consider starting from 0xffff so the checksum of a buffer entirely consisting of zeros
    // is correctly calculated as 0.
    uint32_t temp_sum;
    temp_sum = ip_checksum_add(0, data, len);
    return ip_checksum_finish(temp_sum);
}

// calculate ip checksum
uint16_t n_IP::calcIPChecksum() {
    struct iphdr* iph = new iphdr;
    memcpy(iph, this->ip_header, this->getSizeOfIPHeader());
    iph->check = 0;//set Checksum field 0

    uint16_t checksum = ip_checksum(reinterpret_cast<uint16_t*>(iph), iph->ihl*4);

    return checksum;
}

// set ip checksum
void n_IP::setIPChecksum(uint16_t checksum) {
    this->ip_header->check = checksum;
}

// set profer checksum for ip
void n_IP::setProferIPChecksum() {
    this->setIPChecksum(this->calcIPChecksum());
}
