#pragma once
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <functional> 
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
using namespace std;

const USHORT ETHERTYPE_IP = 0x0800;

class Packet {
public:
    struct pcap_pkthdr* header;
    u_char* packet;
    struct ether_header* eth;
    struct iphdr* ip;

private:
    const unsigned int ethHeaderSize = 14;
    const unsigned int ipHeaderSize = 20; // IPv4 =20 , IPv6 = 40
    unsigned int payloadSize;

    unsigned int ethProtocol;
    unsigned int ipProtocol;
    string sourceIP;
    string destinationIP;
    unsigned int sourcePort;
    unsigned int destinationPort;
    unsigned char ethHeader[14];
    unsigned char ipHeader[20];
    unsigned char* payload;
    string rawPacket;

public:
    Packet();
    Packet(const struct pcap_pkthdr* header, const u_char* packet);
    ~Packet();

    string toString();
    void parsePacket();
    void createPacket();
};

// Parse Ethernet header
struct ether_header {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    USHORT ether_type;
};

// Parse IP header
struct iphdr {
    unsigned char ip_hl : 4;
    unsigned char ip_v : 4;
    u_char ip_tos;
    USHORT ip_len;
    USHORT ip_id;
    USHORT ip_off;
    u_char ip_ttl;
    u_char ip_p;
    USHORT ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

// Parse TCP header
struct tcphdr {
    USHORT th_sport;
    USHORT th_dport;
    ULONG th_seq;
    ULONG th_ack;
    USHORT th_flags;
    USHORT th_win;
    USHORT th_sum;
    USHORT th_urp;
};

// Parse UDP header
struct udphdr {
    USHORT uh_sport;
    USHORT uh_dport;
    USHORT uh_len;
    USHORT uh_sum;
};