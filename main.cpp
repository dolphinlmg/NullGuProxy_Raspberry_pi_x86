#include "n_main.h"

using namespace std;

int main() {
    n_Pcap wlan0("wlan0");
    n_Pcap dummy("dum0");

    // open pcap file to log
    file = new n_Pcap_Data("./test.pcap");

    // initialize
    init();

    while (true) {
        // get next packet from wlan0
        n_Frame* packet;
        int res = wlan0 >> packet;
        if (res == 0) continue;
        else if(res == -1 || res == -2) break;

        if (packet->what() == "TCP"){
            n_TCP* tmp = dynamic_cast<n_TCP*>(packet);
            if (!tmp->isFilteredPort(ports)) continue;

            // dump packet data
            cout << packet;

            // send packet to dummy
            dummy << packet;
        }
    }

    return 0;
}
