#ifndef N_MAIN_H
#define N_MAIN_H
#include <iostream>
#include <fstream>
#include <signal.h>
#include "Class/Packet/n_tcp.h"
#include "Class/n_Pcap/n_pcap.h"
#include "Class/n_Pcap/n_pcap_data.h"

using namespace std;

// namespace for main
namespace MAIN {
    static n_Pcap_Data* file;
    static vector<uint16_t> ports;
    static vector<pair<pair<uint32_t, uint32_t>, pair<uint16_t, uint16_t>>> sessions;
    static const char* portFileName = "ports.ng";

    // signal handler for sigint
    [[ noreturn ]] void handler(int s) {
        cout << endl << "Signal Captured: " << s
             << endl << "Exporting to file..." << endl;
        file->exportToFile();
        exit(0);
    }

    bool readPortsFromFile() {
        try {
            ifstream is(portFileName, ios::in);
            if (!is.is_open())
                return false;
            uint16_t tmp;
            while(!is.eof()){
                is >> tmp;
                if (is.good())
                    ports.push_back(tmp);
            }
            is.close();
        } catch (exception& ex) {
           cerr << ex.what() << endl;
           return false;
        }
       return true;
    }

    void init() {
        // read ports from 'ports.ng'
        if (!readPortsFromFile()) {
            cerr << "Error to read port file!" << endl;
            exit(-1);
        }

        // register signal handler
        signal(SIGINT, handler);
    }

    uint32_t parseIP(const char* ip) {
        uint32_t ret = 0;
        uint8_t* p = reinterpret_cast<uint8_t*>(&ret);
        for (size_t i = 0; i < strlen(ip); i++) {
            if(*(ip+i) == '.')
                p++;
            else{
                *p *= 10;
                *p += *(ip+i) - '0';
            }
        }
        return ret;
    }

}

using namespace MAIN;

#endif // N_MAIN_H
