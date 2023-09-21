#include "Packet.h"

Packet::Packet() {
    sourceIP = "";
    destinationIP = "";
    sourcePort = 0;
    destinationPort = 0;
    memset(ethHeader, 0, ethHeaderSize);
    memset(ipHeader, 0, ipHeaderSize);
    payloadSize = 0;
}

Packet::Packet(const struct pcap_pkthdr* header, const u_char* packet) {

    this->header = new struct pcap_pkthdr;  // Allocate memory for header
    memcpy(this->header, header, sizeof(struct pcap_pkthdr));

    this->packet = new u_char[header->caplen];  // Allocate memory for packet data
    memcpy(this->packet, packet, header->caplen);

    eth = (struct ether_header*)packet;
    ethProtocol = ntohs(eth->ether_type);

    ip = (struct iphdr*)(packet + sizeof(struct ether_header));
    ipProtocol = ip->ip_p;

    if(ethProtocol == ETHERTYPE_IP){
        createPacket();
    }
    cout << toString() << endl;
    parsePacket();
}

Packet::~Packet() {
    if (payload) {
        free(payload);
    }

    delete this->header;
    delete[] this->packet;
}

void Packet::createPacket() {

    sourceIP = to_string(static_cast<int>(packet[26])) + "." +
        to_string(static_cast<int>(packet[27])) + "." +
        to_string(static_cast<int>(packet[28])) + "." +
        to_string(static_cast<int>(packet[29]));

    destinationIP = to_string(static_cast<int>(packet[30])) + "." +
        to_string(static_cast<int>(packet[31])) + "." +
        to_string(static_cast<int>(packet[32])) + "." +
        to_string(static_cast<int>(packet[33]));

    sourcePort = (packet[34] << 8 | packet[35]);
    destinationPort = (packet[36] << 8 | packet[37]);

    for (unsigned int index = 0; index < ethHeaderSize; index++) {
        ethHeader[index] = packet[index];
    }
    for (unsigned int index = 0; index < ipHeaderSize; index++) {
        ipHeader[index] = packet[index + ethHeaderSize];

    }

    unsigned int payloadOffset = (ethHeaderSize + ipHeaderSize);
    payloadSize = (header->caplen - payloadOffset);

    if (header->len > 34) {

        payload = (unsigned char*)malloc(payloadSize * sizeof(unsigned char));
        // TEST CONDITION
        if(header->len  > header->caplen){
            cout << "ERROR IN LEN AND CAPLEN" << endl;
            system("pause");
        }

        for (unsigned int index = 0; index < payloadSize; index++) {
            payload[index] = packet[index + payloadOffset];
        }
    }
}

string Packet::toString() {

    ostringstream stringPacket;
    if ( ethProtocol == ETHERTYPE_IP) {

        auto timepoint = std::chrono::system_clock::from_time_t(header->ts.tv_sec);
        auto timeinfo = std::chrono::system_clock::to_time_t(timepoint);
        struct tm tm_info;
        localtime_s(&tm_info, &timeinfo);
        char dateString[80];
        strftime(dateString, sizeof(dateString), "%Y-%m-%d %H:%M:%S", &tm_info);


        stringPacket << dateString << "\n"
            << "[" << this->sourceIP
            << "(" << this->sourcePort << ")]"
            << " --> "
            << "[" << this->destinationIP
            << "(" << this->destinationPort << ")]"
            << "\n";

        stringPacket << "Length: " << header->len << " bytes." << "\n";

        stringPacket << "EthHeader: ";
        for (unsigned int i = 0; i < ethHeaderSize; ++i) {
            stringPacket << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(ethHeader[i]) << " ";
        }
        stringPacket << "\n";

        stringPacket << "IpHeader: ";
        for (unsigned int i = 0; i < ipHeaderSize; ++i) {
            stringPacket << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(ipHeader[i]) << " ";
        }
        stringPacket << "\n";

        stringPacket << "Payload: ";
        for (unsigned int i = 0; i < payloadSize; ++i) {
            stringPacket << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(payload[i]) << " ";
        }
        stringPacket << "\n";

    } else {
        stringPacket << "Other Packet: ";
        for (unsigned int i = 0; i < header->caplen; ++i) {
            stringPacket << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(packet[i]) << " ";
        }
        stringPacket << "\n";

    }

    rawPacket = stringPacket.str();

    return rawPacket;
}

void Packet::parsePacket() {

    if (ethProtocol == ETHERTYPE_IP) {
        cout << "Ethernet Protocol : IP " << endl;
        
        if (ipProtocol == IPPROTO_TCP) {
            cout << "IP Protocol: TCP" << endl;
            struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip->ip_hl * 4));
            // Print TCP port numbers, sequence number, etc.

        } else if (ipProtocol == IPPROTO_UDP) {
            cout << "IP Protocol: UDP" << endl;
            struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + (ip->ip_hl * 4));
            // Print UDP port numbers, length, etc.

        } else {
            cout << "IP Protocol: Other" << endl;
        }
    } else {
        cout << "Ethernet Protocol: Other" << endl;
    }
}
