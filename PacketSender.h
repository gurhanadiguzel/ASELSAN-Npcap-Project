#pragma once
#include "Packet.h"
#include "httplib.h"

#pragma comment(lib, "ws2_32.lib")

class PcapWriter {
   private:
    pcap_t* pcapFile;
    pcap_dumper_t* pcapDumper;

   public:
    PcapWriter();
    ~PcapWriter();

    void openPcapWriter(const char* fileName);
    void writePacket(Packet* packet);
    void closePcapWriter();
};

class SocketWriter {
   private:
    SOCKET TCPServerSocket;
    int iCloseSocket;

    struct sockaddr_in TCPServerAdd = {0};
    struct sockaddr_in TCPClientAdd = {0};
    int iTCPClientAdd;

    int iBind = 0;
    int iListen = 0;
    int iResult = 0;

    SOCKET sAcceptSocket = 0;

    int iSend = 0;
    char SenderBuffer[65536] = {0};
    int iSenderBuffer = 0;

    int iRecv = 0;
    char RecvBuffer[1024] = {0};
    int iRecvBuffer = 0;

   public:
    void establishSocketConnection();
    void sendPacketThroughSocket(string packetData);
    void acceptConnections();
};

class HttpServer {
   public:
    httplib::Server svr;
    int device = 0;
    std::function<void()> startFn;
    std::function<void()> stopFn;
    std::function<void()> changeFn;

   public:
    void openHttpServer(std::function<void()> startFn, std::function<void()> stopFn);
};

class PacketSender {
   public:
    int transmissionMode;

   public:
    PcapWriter pcapWriter;
    SocketWriter socketWriter;
    HttpServer httpServer;
    std::function<void()> startFunction;
    std::function<void()> stopFunction;
    std::function<void()> changeFunction;

   public:
    void setFunctions(std::function<void()> startFn, std::function<void()> stopFn, std::function<void()> changeFn);
    void setTransmissionMode(int mode);
    void sendPacket(Packet* packetData);
    void writePacketToTextFile(string packetData);
};
