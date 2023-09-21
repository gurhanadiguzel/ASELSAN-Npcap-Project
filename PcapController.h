#pragma once
#include "PacketSender.h"
#include "Sniffer.h"

class PcapController {
public:
    Sniffer sniffer;
    static PacketSender packetSender ;
    bool deviceSelected = false;

public:
    PcapController();
    void configure();
    void initialize();
    void packetReceived(Packet* packetData);
    void startSniffer();
    void stopSniffer();
    void changeSniffer();
};
