import os
import subprocess
import csv
from scapy.all import rdpcap


class WireSharkManager:
    def __init__(self, interface, capture_duration, output_folder):
        self.interface = interface
        self.capture_duration = capture_duration
        self.output_folder = output_folder

    def run_capture(self):
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)

        output_file = f"{self.output_folder}/results.pcap"
        capture_command = [
            "tshark", "-i", self.interface,
            "-a", f"duration:{self.capture_duration}",
            "-w", output_file
        ]
        try:
            subprocess.run(capture_command, check=True)
            print(f"File saved: {output_file}")
            print("!!!   successful   !!!")
            return output_file
        except subprocess.CalledProcessError as e:
            print(f"Capture failed: {e}")
            return None

    @staticmethod
    def extract_devices(pcap_file):
        devices = []
        packets = rdpcap(pcap_file)

        for packet in packets:
            mac_src = packet['Ethernet'].src if packet.haslayer('Ethernet') else None
            mac_dst = packet['Ethernet'].dst if packet.haslayer('Ethernet') else None
            ip_src = packet['IP'].src if packet.haslayer('IP') else None
            ip_dst = packet['IP'].dst if packet.haslayer('IP') else None

            # Append non-empty device data
            if mac_src or ip_src:
                devices.append({"MAC": mac_src, "IP": ip_src})
            if mac_dst or ip_dst:
                devices.append({"MAC": mac_dst, "IP": ip_dst})

        return devices

    @staticmethod
    def save_to_csv(devices, csv_file):
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["MAC Address", "IP Address"])
            for device in devices:
                writer.writerow([device.get("MAC", "N/A"), device.get("IP", "N/A")])

        print(f"Devices information saved to: {csv_file}")

    def capture_and_extract(self):
        pcap_file = self.run_capture()
        if pcap_file:
            devices = self.extract_devices(pcap_file)
            csv_file = f"{self.output_folder}/devices.csv"
            self.save_to_csv(devices, csv_file)


# Initialize and run WireSharkManager
wireshark_manager = WireSharkManager("en0", 10, "/Users/ardafikretazakli/Desktop/development/wiresharkData")
wireshark_manager.capture_and_extract()
