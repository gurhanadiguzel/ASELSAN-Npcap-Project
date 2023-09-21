#pragma once
#include "Packet.h"
#include <nlohmann/json.hpp> 


class PcapController;

class Sniffer {
    private:
        static pcap_t* handle;
        static PcapController* pcapController;
        static pcap_if_t* selectedDevice;
        static pcap_if_t* deviceList;

    public:
        static unsigned int packetCounter;

    public:
        //Sniffer();
        ~Sniffer();

        void attachController(PcapController* ctrl);
        void selectDevice(int device);
        void openLiveCapture();
        void startPacketCapture();
        void stopPacketCapture();
        void listDevicesToJson();

        static void processCapturedPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
};
