#include "Sniffer.h"

#include "PcapController.h"

PcapController* Sniffer::pcapController = nullptr;
pcap_if_t* Sniffer::selectedDevice = nullptr;
pcap_if_t* Sniffer::deviceList = nullptr;
pcap_t* Sniffer::handle = nullptr;
unsigned int Sniffer::packetCounter = 1;

Sniffer::~Sniffer() {
    if (handle) {
        pcap_close(handle);
    }
}

void Sniffer::attachController(PcapController* ctrl) {
    pcapController = ctrl;
}

void Sniffer::listDevicesToJson() {
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    int deviceCount = 1;

    // Get a list of available devices
    if (pcap_findalldevs(&deviceList, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        exit(1);
    }

    nlohmann::json devicesJson;
    for (selectedDevice = deviceList; selectedDevice; selectedDevice = selectedDevice->next) {
        std::cout << deviceCount << "- Device:" << selectedDevice->name << "\n" << "Description: " << selectedDevice->description << "\n" << endl;
        deviceCount++;

        // Append device information to the JSON array
        nlohmann::json deviceJson;
        deviceJson["name"] = selectedDevice->name;
        deviceJson["description"] = selectedDevice->description;
        devicesJson.push_back(deviceJson);
    }

    std::ofstream outputFile("devices.json");
    if (outputFile.is_open()) {
        outputFile << devicesJson.dump(4);  // Write the JSON with pretty formatting
        outputFile.close();
        std::cout << "Device information written to devices.json." << std::endl;
    }
    else {
        std::cerr << "Error opening devices.json for writing." << std::endl;
    }
}

void Sniffer::selectDevice(int device) {
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    int deviceCount = 1;
    int selectedDeviceIndex;

    // Get a list of available devices
    if (pcap_findalldevs(&deviceList, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        exit(1);
    }

    for (selectedDevice = deviceList; selectedDevice; selectedDevice = selectedDevice->next) {
        std::cout << deviceCount << "- Device:" << selectedDevice->name << "\n" << "Description: " << selectedDevice->description << "\n" << endl;
        deviceCount++;
    }

    // Take input to select device.
    cout << "Enter a Device Number: ";
    if (device == -1) {
        cin >> selectedDeviceIndex;
    } else {
        selectedDeviceIndex = device;
    }

    // Find the selected interface based on index
    if (selectedDeviceIndex < 1 || selectedDeviceIndex >= deviceCount) {
        cout << "Error while selecting device." << endl;
        pcap_freealldevs(deviceList);
        exit(1);
    }

    selectedDevice = deviceList;
    while (selectedDeviceIndex > 1 && selectedDevice) {
        selectedDevice = selectedDevice->next;
        selectedDeviceIndex--;
    }

    if (!selectedDevice) {
        cerr << "Device cannot be found." << endl;
        pcap_freealldevs(deviceList);
        exit(1);
    } else {
        cout << "Device is : " << selectedDevice->name << endl;
    }

    pcap_freealldevs(deviceList);
}

void Sniffer::openLiveCapture() {
    // Open live pcap session in NIC with the selected device
    char errbuf[PCAP_ERRBUF_SIZE];

    cout << "Pcap open live." << endl;
    handle = pcap_open_live(selectedDevice->name, 65535, 0, 100, errbuf);

    if (!handle) {
        cerr << "Error while opening network interface: " << errbuf << std::endl;
        pcap_freealldevs(deviceList);
        exit(1);
    }
}

void Sniffer::startPacketCapture() {
    cout << "Pcap Loop is starting..." << endl;
    pcap_loop(handle, -1, processCapturedPacket, NULL);
}

void Sniffer::stopPacketCapture() {
    if (handle) {
        //pcap_breakloop(handle);
        pcap_close(handle);
    }
}

/*Callback*/
void Sniffer::processCapturedPacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {

    cout << endl;
    for (int i = 0; i < 64; ++i) {
        cout << '-';
    }
    cout << endl;
    cout << "Packet Count is : " << packetCounter << endl;

    Packet newPacket(header, packet);

    if (NULL != pcapController) {
        pcapController->packetReceived(&newPacket);
    }
    packetCounter++;
}