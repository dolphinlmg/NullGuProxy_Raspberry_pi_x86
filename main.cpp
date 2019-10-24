#include "n_main.h"

using namespace std;

int main() {
    n_Pcap wlan0("wlan0");
    n_Pcap loopback("lo");

    // open pcap file to log
    file = new n_Pcap_Data("./test.pcap");

    // initialize
    init();

    while (true) {
        // get next packet from interfaces
        n_Frame *input, *output;
        int input_res = wlan0 >> input;
        int output_res = loopback >> output;

        // break if error occured
        if (input_res == -1 || input_res == -2 || output_res == -1 || output_res == -2) break;

        // if input packet captured
        if (input_res != 0) {
            if (input->what() == "TCP"){
                n_TCP* input_tcp = dynamic_cast<n_TCP*>(input);

                for (auto port : ports) {
                if (input_tcp->isFilteredDstPort(port)) {
                    // dump packet
                    cout << input;

                    // set session
                    pair<pair<uint32_t, uint32_t>, pair<uint16_t, uint16_t>> tmp_pair;
                    tmp_pair.first.first = input_tcp->getIPSrc();
                    tmp_pair.first.second = input_tcp->getIPDst();
                    tmp_pair.second.first = port;
                    tmp_pair.second.second = 1234;
                    sessions.push_back(tmp_pair);

                    // set ip loopback
                    input_tcp->setIPDst(parseIP("127.0.0.1"));

                    // set port loopback
                    input_tcp->setTcpDstPort(1234);

                    // set checksum
                    input_tcp->setProferChecksum();

                    // relay to loopback
                    loopback << input;
                }
                }
            }
        }

        // if output packet captured
        if (output_res != 0) {
            if (output->what() == "TCP"){
                n_TCP* output_tcp = dynamic_cast<n_TCP*>(output);

                for (auto session : sessions)
                if (output_tcp->isFilteredSrcPort(session.second.second)){
                    // dump packet
                    cout << output;

                    // set ip origin
                    output_tcp->setIPDst(session.first.first);
                    output_tcp->setIPSrc(session.first.second);

                    // set port origin
                    output_tcp->setTcpSrcPort(session.second.first);

                    // set checksum
                    output_tcp->setProferChecksum();

                    // relay to origin
                    wlan0 << output;
                }
            }
        }
    }

    return 0;
}
