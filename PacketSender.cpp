#include "PacketSender.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS

void PacketSender::setFunctions(std::function<void()> startFn, std::function<void()> stopFn, std::function<void()> changeFn) {
    startFunction = startFn;
    stopFunction = stopFn;
    changeFunction = changeFn;
}

void PacketSender::setTransmissionMode(int mode) {
    transmissionMode = mode;
    // If TCP, init socket (server)
    if (transmissionMode == 1) {
        socketWriter.establishSocketConnection();
    } else if (transmissionMode == 2) {
        pcapWriter.openPcapWriter("output.pcap");
    } else if (transmissionMode == 4) {
        pcapWriter.openPcapWriter("output.pcap");
        std::thread httpThread(&HttpServer::openHttpServer, &httpServer, startFunction, stopFunction);
        httpThread.detach();
    }
}

void PacketSender::sendPacket(Packet* packetData) {

    if (transmissionMode == 1) {
        string newPacketString(packetData->toString());
        socketWriter.sendPacketThroughSocket(newPacketString);

    } else if (transmissionMode == 2 || transmissionMode == 4) {
        pcapWriter.writePacket(packetData);

    } else if (transmissionMode == 3) {
        string newPacketString(packetData->toString());
        writePacketToTextFile(newPacketString);

    }
}

void PacketSender::writePacketToTextFile(string packetData) {

    // Open the text file for writing, appending to it if it exists
    std::ofstream outFile("output.txt", std::ios::out | std::ios::app);
    if (!outFile.is_open()) {
        std::cerr << "Failed to open output.txt" << std::endl;
        return;
    }

    outFile << packetData << std::endl;
    outFile.close();
}

void SocketWriter::establishSocketConnection() {
    iTCPClientAdd = sizeof(TCPClientAdd);

    // STEP-2 Fill the structure
    TCPServerAdd.sin_family = AF_INET;
    //TCPServerAdd.sin_addr.s_addr = inet_addr("127.0.0.1");
    InetPton(AF_INET, TEXT("127.0.0.1"), &(TCPServerAdd.sin_addr));
    TCPServerAdd.sin_port = htons(5151);

    // STEP-3 Socket Creation
    TCPServerSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    u_long iMode = 1;
    iResult = ioctlsocket(TCPServerSocket, FIONBIO, &iMode);
    if (iResult != NO_ERROR) {
        printf("ioctlsocket failed with error: %d\n", iResult);
    }

    if (TCPServerSocket == INVALID_SOCKET) {
        cout << "TCP Server Socket Creation failed!" << WSAGetLastError() << endl;
    }
    cout << "TCP Server Socket Creation Success" << endl;

    // STEP-4 Bind
    iBind = ::bind(TCPServerSocket, (SOCKADDR*)&TCPServerAdd, sizeof(TCPServerAdd));
    if (iBind == SOCKET_ERROR) {
        cout << "Binding failed & Error No :" << WSAGetLastError() << endl;
    }
    cout << "Binding Success" << endl;

    // STEP-5 Listen
    iListen = ::listen(TCPServerSocket, 2);
    if (iListen == SOCKET_ERROR) {
        cout << "Listen failed & Error no: " << WSAGetLastError() << endl;
    }
    cout << "Listen Success" << endl;

    // STEP-6 Accept and Loop
    sAcceptSocket = ::accept(TCPServerSocket, (SOCKADDR*)&TCPClientAdd, &iTCPClientAdd);
    std::thread acceptThread(&SocketWriter::acceptConnections, this);
    acceptThread.detach();
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void SocketWriter::acceptConnections() {
    while (true) {

        if (sAcceptSocket == INVALID_SOCKET) {
            SOCKET acceptedSocket = accept(TCPServerSocket, (SOCKADDR*)&TCPClientAdd, &iTCPClientAdd);
            sAcceptSocket = acceptedSocket;  // Update sAcceptSocket

            if (sAcceptSocket != INVALID_SOCKET) {
                std::cout << "Connection Accepted" << std::endl;
            }
        }
        else {
            iResult = recv(sAcceptSocket, RecvBuffer, sizeof(RecvBuffer), MSG_PEEK);

            if (iResult == 0) {
                std::cout << "Client Disconnected" << std::endl;
                closesocket(sAcceptSocket);
                sAcceptSocket = INVALID_SOCKET;
            }
            else if (iResult == SOCKET_ERROR) {
                int errorCode = WSAGetLastError();
                if (errorCode != WSAEWOULDBLOCK) {
                    std::cerr << "recv() failed with error code: " << errorCode << std::endl;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void SocketWriter::sendPacketThroughSocket(string packetData) {
    if (packetData.length() < sizeof(SenderBuffer)) {
        strcpy_s(SenderBuffer, sizeof(SenderBuffer), packetData.c_str());

    }
    else {
        cout << "String too large for SenderBuffer" << endl;
        return;
    }

    if (sAcceptSocket == INVALID_SOCKET) {
        std::cout << "Accept Failed & Error No: " << WSAGetLastError() << std::endl;
        return;

    }
    else {
        iSenderBuffer = strlen(SenderBuffer) + 1;
        iSend = send(sAcceptSocket, SenderBuffer, iSenderBuffer, 0);
        if (iSend == SOCKET_ERROR) {
            cout << "Sending Failed & Error No: " << WSAGetLastError() << endl;
            iCloseSocket = closesocket(sAcceptSocket);
            sAcceptSocket = INVALID_SOCKET;
            return;
        }
        cout << "Data Sending Succes in Loop" << endl;
    }
}

PcapWriter::PcapWriter() {
    pcapFile = nullptr;
    pcapDumper = nullptr;
}

PcapWriter::~PcapWriter() {
    closePcapWriter();
}

void PcapWriter::openPcapWriter(const char* fileName) {
    pcapFile = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcapFile == nullptr) {
        std::cerr << "Error opening pcap file for writing." << std::endl;
        return;
    }

    pcapDumper = pcap_dump_open(pcapFile, fileName);
    if (pcapDumper == nullptr) {
        std::cerr << "Error opening pcap dumper." << std::endl;
        pcap_close(pcapFile);
        return;
    }
}

void PcapWriter::writePacket(Packet* packet) {
    pcap_dump((u_char*)pcapDumper, packet->header, packet->packet);
}

void PcapWriter::closePcapWriter() {
    if (pcapDumper != nullptr) {
        pcap_dump_close(pcapDumper);
    }

    if (pcapFile != nullptr) {
        pcap_close(pcapFile);
    }
}

void HttpServer::openHttpServer(std::function<void()> startFn, std::function<void()> stopFn) {

    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        // Read the contents of index.html
        std::ifstream file("index.html");
        if (file) {
            std::ostringstream content;
            content << file.rdbuf();
            file.close();

            // Set the content of the response to the contents of index.html
            res.set_content(content.str(), "text/html");
        }
        else {
            // File not found, set an error response
            res.status = 404;
            res.set_content("File not found", "text/plain");
        }
        }
    );

    svr.Get("/selectDevice", [this](const httplib::Request& req, httplib::Response& res) {
        // Extract the device number from the query parameters
        int deviceNumber = -1; // Default value indicating no device number
        if (req.has_param("deviceNumber")) {
            deviceNumber = std::stoi(req.get_param_value("deviceNumber"));
            device = deviceNumber;
        }

        // Process the device number as needed
        if (deviceNumber >= 1 && deviceNumber <= 8) {
            res.set_content("Device has been selected!", "text/plain");
        }
        else {
            res.set_content("Device cannot be selected!", "text/plain");
        }
        }
    );

    svr.Get("/startFlag", [this,startFn](const httplib::Request& req, httplib::Response& res) {
        startFn();
        res.set_content("Start flag set.", "text/plain");
        }
    );

    svr.Get("/stopFlag", [this,stopFn](const httplib::Request& req, httplib::Response& res) {
        stopFn();
        res.set_content("Stop flag set.", "text/plain");
        }
    );

    svr.Get("/changeFlag", [this](const httplib::Request& req, httplib::Response& res) {
        device = 0;
        res.set_content("Change flag set.", "text/plain");
        }
    );

    svr.Get("/download", [](const httplib::Request& req, httplib::Response& res) {
        // Set headers for downloading
        res.set_header("Content-Disposition", "attachment; filename=output.pcap");
        res.set_header("Content-Type", "application/octet-stream");

        // Open and read the "output.pcap" file
        std::ifstream file("output.pcap", std::ios::binary);
        if (file) {
            std::ostringstream content;
            content << file.rdbuf();
            file.close();

            // Set the content of the response to the contents of "output.pcap"
            res.set_content(content.str(), "application/octet-stream");
        }
        else {
            // File not found, set an error response
            res.status = 404;
            res.set_content("File not found", "text/plain");
        }
        }
    );

    // Serve static files from the current directory
    svr.set_mount_point("/", ".");

    svr.listen("localhost", 5152);
}
