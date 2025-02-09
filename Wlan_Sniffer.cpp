#include <pcap.h>
#include <iostream>
#include <cstring>
#include <map>
#include <ncurses.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cmath>

struct DeviceInfo {
    std::string macAddress;
    int signalStrength;
    int packetCount;
};

std::map<std::string, DeviceInfo> deviceMap;
std::mutex deviceMapMutex;
std::atomic<bool> capturePaused(false);
std::atomic<int> currentView(0);
std::vector<std::string> filterMacAddresses;

const double A = -40;
const double n = 3.0;

std::string parseMacAddress(const u_char* packet, int offset) {
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             packet[offset], packet[offset + 1], packet[offset + 2],
             packet[offset + 3], packet[offset + 4], packet[offset + 5]);
    return std::string(mac);
}

double estimateDistance(int rssi) {
    return std::pow(10.0, (A - rssi) / (10 * n));
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet) {
    if (capturePaused) return;

    int offset = 10;
    std::string macAddress = parseMacAddress(packet, offset);
    int signalStrength = packet[header->caplen - 2];

    std::lock_guard<std::mutex> lock(deviceMapMutex);
    if (deviceMap.find(macAddress) == deviceMap.end()) {
        deviceMap[macAddress] = {macAddress, signalStrength, 1};
    } else {
        deviceMap[macAddress].packetCount++;
    }
}

void drawSignalStrengthBars() {
    int row = 5;
    deviceMapMutex.lock();
    for (const auto& entry : deviceMap) {
        const DeviceInfo& device = entry.second;
        if (!filterMacAddresses.empty() && 
            std::find(filterMacAddresses.begin(), filterMacAddresses.end(), device.macAddress) == filterMacAddresses.end()) {
            continue;
        }

        move(row, 0);
        clrtoeol();
        printw("%-20s: ", device.macAddress.c_str());
        int barLength = std::min(device.signalStrength / 2, 50);
        for (int i = 0; i < barLength; ++i) printw("|");
        printw(" (%d dBm)", device.signalStrength);
        row++;
    }
    deviceMapMutex.unlock();
}

void displayOverlay() {
    initscr();
    noecho();
    cbreak();
    curs_set(0);
    keypad(stdscr, TRUE);

    while (true) {
        clear();
        printw("=== WLAN Device Scanner ===\n");
        printw("Press 'p' to pause/resume, 's' to save, 'f' to filter by MAC, 'v' to switch view, 'L' to show suspicious devices, 'q' to quit\n");
        printw("%-20s | %-15s | %-12s\n", "MAC Address", "Signal Strength", "Packet Count");
        printw("-----------------------------------------------\n");

        if (currentView == 0) {
            deviceMapMutex.lock();
            for (const auto& entry : deviceMap) {
                const DeviceInfo& device = entry.second;
                printw("%-20s | %-15d | %-12d\n", device.macAddress.c_str(), device.signalStrength, device.packetCount);
            }
            deviceMapMutex.unlock();
        } else if (currentView == 1) {
            drawSignalStrengthBars();
        }

        refresh();

        int ch = getch();
        if (ch == 'q') {
            break;
        } else if (ch == 'p') {
            capturePaused = !capturePaused;
        } else if (ch == 's') {
            deviceMapMutex.lock();
            std::ofstream outFile("device_info.txt");
            for (const auto& entry : deviceMap) {
                const DeviceInfo& device = entry.second;
                outFile << "MAC: " << device.macAddress
                        << " | Signal Strength: " << device.signalStrength
                        << " | Packet Count: " << device.packetCount << std::endl;
            }
            deviceMapMutex.unlock();
            outFile.close();
            printw("Device information saved to device_info.txt\n");
        } else if (ch == 'f') {
            echo();
            char macFilter[18];
            printw("Enter MAC Address to filter: ");
            getnstr(macFilter, sizeof(macFilter) - 1);
            noecho();
            filterMacAddresses.push_back(macFilter);
            printw("Filter added for: %s\n", macFilter);
        } else if (ch == 'v') {
            currentView = (currentView + 1) % 2;
        } else if (ch == 'L') {
            clear();
            printw("=== Suspicious Devices Nearby ===\n");
            deviceMapMutex.lock();
            bool foundSuspicious = false;
            for (const auto& entry : deviceMap) {
                const DeviceInfo& device = entry.second;
                double distance = estimateDistance(device.signalStrength);
                if (distance < 10.0) {
                    printw("MAC: %-20s | Distance: %.2f meters | Signal: %-3d dBm\n", device.macAddress.c_str(), distance, device.signalStrength);
                    foundSuspicious = true;
                }
            }
            deviceMapMutex.unlock();
            if (!foundSuspicious) {
                printw("No suspicious devices nearby.\n");
            }
            printw("Press any key to return.\n");
            refresh();
            getch();
        }
        napms(500);
    }

    endwin();
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs, * dev;
    pcap_t* handle;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    dev = alldevs;
    if (dev == nullptr) {
        std::cerr << "No devices found!" << std::endl;
        return 1;
    }

    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Starting WLAN device scanning on: " << dev->name << std::endl;

    std::thread overlayThread(displayOverlay);

    pcap_loop(handle, 0, packetHandler, nullptr);

    overlayThread.join();
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
