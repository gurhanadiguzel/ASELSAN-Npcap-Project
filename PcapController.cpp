#include "PcapController.h"

#include "Sniffer.h"

// Define static member variable
PacketSender PcapController::packetSender;

PcapController::PcapController() {
    sniffer.attachController(this);
    packetSender.setFunctions([this]() { startSniffer(); }, [this]() { stopSniffer(); }, [this]() { changeSniffer(); });
}

void PcapController::configure() {

    int input;
    // Configure output
    cout << "1 - Send data to TCP Socket." << endl;
    cout << "2 - Print out data to Pcap File." << endl;
    cout << "3 - Print out data to Text File." << endl;
    cout << "4 - Print out data to HTTP Server." << endl;
    cout << "Enter a Number for What to do with the data: ";
    cin >> input;
    cout << endl;

    if (input < 1 || input >4) {
        cerr << "INVALID BUTTON, Please Try Again" << endl;
        exit(1);
    }

    // Configure packetSender mode
    packetSender.setTransmissionMode(input);
}

void PcapController::initialize() {
    // PCAP >> Select network interface to capture
    if (packetSender.transmissionMode != 4) {
        startSniffer();

    } else {
        // BUSY WAIT
        sniffer.listDevicesToJson();
        while (1) {}
    }
}

void PcapController::packetReceived(Packet* packetData) {
    packetSender.sendPacket(packetData);
}

void PcapController::startSniffer() {
    if (packetSender.transmissionMode == 4) {
        while (deviceSelected == false) {
            if (packetSender.httpServer.device != 0)
                deviceSelected = true;
        }
        sniffer.selectDevice(packetSender.httpServer.device);

    } else {
        sniffer.selectDevice(-1);
    }
    sniffer.openLiveCapture();
    sniffer.startPacketCapture();
}

void PcapController::stopSniffer() {
    sniffer.stopPacketCapture();
}

void PcapController::changeSniffer() {
    deviceSelected = false;
    sniffer.packetCounter = 0;
    startSniffer();
}