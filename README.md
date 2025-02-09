# WLAN Device Scanner

A WLAN device scanner implemented in C++ using `pcap` and `ncurses` for live monitoring and displaying of wireless devices in your vicinity. It captures WLAN packets and displays information about devices based on their MAC address, signal strength, and packet count.

## Features

- **Live Device Scanning**: Real-time scanning of WLAN devices nearby and capturing their MAC address, signal strength (RSSI), and packet count.
- **Signal Strength Visualization**: Display signal strength as a bar chart in `ncurses`.
- **Device Filtering**: Allows filtering by MAC address to focus on specific devices.
- **Suspicious Device Detection**: Identify and display devices that are within close proximity based on their signal strength.
- **Save Device Information**: Save scanned device information to a text file for later analysis.
- **Pause/Resume Scanning**: Pause and resume packet capture as needed.

## Requirements

- **libpcap**: A library for network packet capture.
- **ncurses**: A library for creating terminal-based user interfaces.
- **C++11 or newer**: For compiling the C++ source code.

### Installing Dependencies on Linux

To install the necessary dependencies, use the following commands:

```bash
sudo apt-get update
sudo apt-get install libpcap-dev libncurses5-dev g++ make
```
- **libpcap-dev**: Provides the pcap library for capturing network packets.
- **libncurses5-dev**: Provides the ncurses library for terminal-based UI.
- **g++**: The GNU C++ compiler.
- **make**: A build automation tool.

## Build Instructions
1. **Clone the repository to your local machine**:
```bash
git clone https://github.com/yourusername/wlan-device-scanner.git
cd wlan-device-scanner
```
2. Compile the project using **g++**:
```bash
g++ -o wlan_device_scanner main.cpp -lpcap -lncurses -std=c++11
```
- This command will compile the code and generate an executable named **wlan_device_scanner**.
  
 ## Usage Instructions
1. **Running the Scanner**:
- Once compiled, you can run the WLAN device scanner using:
```bash
sudo ./wlan_device_scanner
```
- **Note**: You need sudo to run the program because it requires permission to capture network packets.
2. **Key Commands in the Dashboard**:
- **'p'**: Pause or resume scanning.
- **'s'**: Save scanned device information to a file (device_info.txt).
- **'f'**: Filter devices by a specific MAC address.
- **'v'**: Switch between the default list view and a signal strength bar view.
- **'L'**: View suspicious devices nearby based on signal strength (within 10 meters).
- **'q'**: Quit the application.
3. **Saving the Device Information**:
When you press **'s'**, the scanned device information (MAC address, signal strength, and packet count) is saved to device_info.txt.

4. **Filtering Devices**:
When you press **'f'**, you can enter a MAC address to filter by. This will only display the filtered device(s) in the dashboard.

5. **Suspicious Device Detection**:
When you press **'L'**, it will show all devices within close proximity (less than 10 meters) based on their signal strength. Devices with a strong signal will be considered "suspicious."

## Example Output
In the terminal, the device scanner will output a list of devices with their MAC addresses, signal strength, and packet count.
```bash
=== WLAN Device Scanner ===
Press 'p' to pause/resume, 's' to save, 'f' to filter by MAC, 'v' to switch view, 'L' to show suspicious devices, 'q' to quit
MAC Address         | Signal Strength | Packet Count
----------------------------------------------------
00:1A:2B:3C:4D:5E   | -60 dBm         | 5
01:2B:3C:4D:5E:6F   | -70 dBm         | 3
```
When switching to the bar chart view (press **'v'**), you’ll see something like:
```bash
00:1A:2B:3C:4D:5E: ||||||| ( -60 dBm)
01:2B:3C:4D:5E:6F: ||||| ( -70 dBm)
```
## Saving Device Information
If you press **'s'**, a file called device_info.txt will be created with information about the scanned devices, like this:
```bash
MAC: 00:1A:2B:3C:4D:5E | Signal Strength: -60 | Packet Count: 5
MAC: 01:2B:3C:4D:5E:6F | Signal Strength: -70 | Packet Count: 3
```
## Troubleshooting
- If you encounter any issues with capturing packets, ensure that you have the proper permissions (e.g., run as sudo).
- Make sure your system supports libpcap and ncurses correctly.

