#include "n_pcap.h"

// constructor that open pcap live and initialize member variables
n_Pcap::n_Pcap(const char* dev) {
    this->handle = pcap_open_live(dev, BUFSIZ, 1, 1, this->errBuf);
    if (handle == nullptr) {
        std::cerr << "Cannot open device: " << dev << std::endl;
        exit(1);
    }
    this->header = nullptr;
    this->packet = nullptr;
}

// destructor that close pcap
n_Pcap::~n_Pcap() {
    pcap_close(this->handle);
}

// send packet with handle
int n_Pcap::sendPacket(n_Frame* packet) const {
    return pcap_sendpacket(this->handle, packet->getFrameData(), static_cast<int>(packet->getLength()));
}

// receve packet in header, packet
int n_Pcap::getNextPacket() {
    return pcap_next_ex(this->handle, &this->header, &this->packet);
}

// return packet header
pcap_pkthdr* n_Pcap::getPacketHeader() {
    return this->header;
}

// return packet data
const uint8_t* n_Pcap::getPacketData() {
    return this->packet;
}

// return packet length
uint32_t n_Pcap::getPacketLength(){
    if (this->header != nullptr)
        return this->header->len;
    return 0;
}

// return appropriate packet object
n_Frame* n_Pcap::recognizePacket() {
    n_Frame* ret = new n_Ethernet(this->packet, this->header);
    if (dynamic_cast<n_Ethernet*>(ret)->getEthType() == ntohs(0x0800)){
        delete ret;
        ret = new n_IP(this->packet, this->header);
        if (dynamic_cast<n_IP*>(ret)->getProtocol() == 6){
            delete ret;
            ret = new n_TCP(this->packet, this->header);
        }
    }
    return ret;
}

// get next packet & recognize packet, returns result of getNextPacket()
int n_Pcap::operator>>(n_Frame* &packet) {
    int ret = this->getNextPacket();
    packet = this->recognizePacket();
    return ret;
}

// send packet, returns result of sendPacket()
int n_Pcap::operator<<(n_Frame* &packet) {
    return this->sendPacket(packet);
}
