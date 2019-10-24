TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap

SOURCES += \
    Class/Packet/n_ethernet.cpp \
    Class/Packet/n_frame.cpp \
    Class/Packet/n_ip.cpp \
    Class/Packet/n_tcp.cpp \
    Class/n_Pcap/n_pcap.cpp \
    Class/n_Pcap/n_pcap_data.cpp \
        main.cpp

HEADERS += \
    Class/Packet/n_ethernet.h \
    Class/Packet/n_frame.h \
    Class/Packet/n_ip.h \
    Class/Packet/n_tcp.h \
    Class/n_Pcap/n_pcap.h \
    Class/n_Pcap/n_pcap_data.h \
    n_main.h
