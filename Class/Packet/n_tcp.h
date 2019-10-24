#ifndef N_TCP_H
#define N_TCP_H
#include <netinet/tcp.h>
#include <vector>
#include "n_ip.h"

//#pragma pack(push, 1)
typedef struct pseudoHeader {
    uint32_t src;
    uint32_t dst;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcplen;
} pseudohdr;
//#pragma pack(pop)

class n_TCP : public n_IP
{
public:
    n_TCP(uint8_t* data, pcap_pkthdr* header);
    n_TCP(const uint8_t* data, pcap_pkthdr* header);
    tcphdr* getTcpData() const;
    uint32_t getSizeOfTcpHeader() const;
    bool isTLS() const ;
    bool isFilteredDstPort(std::vector<uint16_t> v) const;
    bool isFilteredDstPort(uint16_t port) const;
    bool isFilteredSrcPort(std::vector<uint16_t> v) const;
    bool isFilteredSrcPort(uint16_t port) const;
    bool isFilteredPort(std::vector<uint16_t> v) const;
    std::string what() const override { return "TCP"; }
    //TODO: Add Methods
    uint16_t calcTCPChecksum();
    void setTCPChecksum(uint16_t ckecksum);
    void setProferTCPChecksum();
    void setProferChecksum();
    void setTcpDstPort(uint16_t port);
    uint16_t getTcpDstPort() const;
    void setTcpSrcPort(uint16_t port);
    uint16_t getTcpSrcPort() const;

private:
    uint16_t in_checksum(uint16_t *ptr,int nbytes);
    tcphdr* tcp_header;
};

#endif // N_TCP_H
