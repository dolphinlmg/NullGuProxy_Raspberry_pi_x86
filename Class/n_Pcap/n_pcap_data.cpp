#include "n_pcap_data.h"

n_Pcap_Data::n_Pcap_Data(const char* fileName) {
    this->fileName = fileName;

    this->fileHeader = new pcap_file_header;

    // setting file header
    this->fileHeader->magic = 0xa1b2c3d4;
    this->fileHeader->version_major = 2;
    this->fileHeader->version_minor = 4;
    this->fileHeader->thiszone = 0;
    this->fileHeader->sigfigs = 0;
    this->fileHeader->snaplen = 0x40000;
    this->fileHeader->linktype = 1;

    // open file
    this->os = std::ofstream(this->fileName, std::ios::out | std::ios::binary);
    try {
        // write file header
        this->os.write(reinterpret_cast<const char*>(this->fileHeader), sizeof(pcap_file_header));
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
    }
}

// add packet to vector
bool n_Pcap_Data::push_packet(n_Frame* packet) {
    this->packetList.push_back(packet);
    n_pcap_fpkthdr* tmp_header = new n_pcap_fpkthdr;
    tmp_header->ts_sec = static_cast<uint32_t>(packet->getFrameHeader()->ts.tv_sec);
    tmp_header->ts_usec = static_cast<uint32_t>(packet->getFrameHeader()->ts.tv_usec);
    tmp_header->incl_len = packet->getFrameHeader()->len;
    tmp_header->orig_len = packet->getFrameHeader()->len;
    this->packetHeader.push_back(tmp_header);
    try {
        // write packet header
        this->os.write(reinterpret_cast<const char*>(tmp_header), sizeof(n_pcap_fpkthdr));
        // write packet data
        this->os.write(reinterpret_cast<const char*>(packet->getFrameData()), signed(tmp_header->orig_len));
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return false;
    }
    return true;
}

// export to file
void n_Pcap_Data::exportToFile() {
    this->os.flush();
}

// destructor
n_Pcap_Data::~n_Pcap_Data() {
    this->os.close();
}

// push & save packet
bool n_Pcap_Data::operator<<(n_Frame* &packet) {
    return this->push_packet(packet);
}
