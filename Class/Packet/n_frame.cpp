#include "n_frame.h"

// default constructor setting data to nullptr
n_Frame::n_Frame() { this->data = nullptr; }

// constructor with uint8_t*
n_Frame::n_Frame(uint8_t* data, pcap_pkthdr* header) {
    this->data = new uint8_t [header->len];
    if (this->data != nullptr)
        memcpy(this->data, data, static_cast<size_t>(header->len));
    this->header = new pcap_pkthdr;
    memcpy(this->header, header, sizeof(pcap_pkthdr));
}

// constructor with const uint8_t*
n_Frame::n_Frame(const uint8_t* data, pcap_pkthdr* header) {
    this->data = new uint8_t [header->len];
    if (this->data != nullptr)
        memcpy(this->data, data, static_cast<size_t>(header->len));
    this->header = new pcap_pkthdr;
    memcpy(this->header, header, sizeof(pcap_pkthdr));
}

//destructor: delete[] data
n_Frame::~n_Frame(){
    if (this->data != nullptr)
        delete[] this->data;
}

uint32_t n_Frame::getLength() const {
    return this->header->len;
}

// set length of packet
void n_Frame::setFrameHeader(pcap_pkthdr* header){
    this->header = new pcap_pkthdr;
    memcpy(this->header, header, sizeof(pcap_pkthdr));
}

// set data with uint8_t*
void n_Frame::setFrameData(uint8_t* data, uint32_t len){
    if (this->data != nullptr){
        delete[] this->data;
    }
    this->data = new uint8_t [len];
    memcpy(this->data, data, static_cast<size_t>(len));
}

// set data with const uint8_t*
void n_Frame::setFrameData(const uint8_t* data, uint32_t len){
    if (this->data != nullptr){
        delete[] this->data;
    }
    this->data = new uint8_t [len];
    memcpy(this->data, data, static_cast<size_t>(len));
}

// return data
uint8_t* n_Frame::getFrameData() const {
    return this->data;
}

pcap_pkthdr* n_Frame::getFrameHeader() {
    return this->header;
}

// hex dump
template<class Elem, class Traits>
inline void hex_dump(const void* aData, std::size_t aLength, std::basic_ostream<Elem, Traits>& aStream, std::size_t aWidth = 16)
{
    const char* const start = static_cast<const char*>(aData);
    const char* const end = start + aLength;
    const char* line = start;
    while (line != end)
    {
        aStream.width(4);
        aStream.fill('0');
        aStream << std::hex << line - start << " : ";
        std::size_t lineLength = std::min(aWidth, static_cast<std::size_t>(end - line));
        for (std::size_t pass = 1; pass <= 2; ++pass)
        {
            for (const char* next = line; next != end && next != line + aWidth; ++next)
            {
                char ch = *next;
                switch(pass)
                {
                case 2:
                    aStream << (ch < 32 ? '.' : ch);
                    break;
                case 1:
                    if (next != line)
                        aStream << " ";
                    aStream.width(2);
                    aStream.fill('0');
                    aStream << std::hex << static_cast<int>(static_cast<unsigned char>(ch));
                    break;
                }
            }
            if (pass == 1 && lineLength != aWidth)
                aStream << std::string(aWidth * 3 - lineLength * 3, ' ');
            aStream << " ";
        }
        aStream << std::endl;
        line = line + lineLength;
    }
}

// dump packet with const uint8_t*
std::string n_Frame::dumpPacket() {
    std::stringstream ss;
    uint32_t len = this->header->len;
    hex_dump(this->getFrameData(), static_cast<size_t>(len), ss);
    return ss.str();
}

// dump packet with operator<<
std::ostream& operator<<(std::ostream& os,  n_Frame* &packet) {
    os << packet->what() << ": " << packet->getLength() << std::endl
       << packet->dumpPacket() << std::endl;
    return os;
}
