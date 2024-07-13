import subprocess
import csv
from scapy.all import rdpcap
from scapy.layers.l2 import Ether


class WireSharkManager:
    def __init__(self, interface, capture_duration, output_folder):
        self.interface = interface
        self.capture_duration = capture_duration
        self.output_folder = output_folder

    def run_capture(self):
        # it could be saved as a csv, but it is not readable from human :D
        output_file = f"{self.output_folder}/results.pcap"
        capture_command = [
            "tshark", "-i", self.interface,
            "-a", f"duration:{self.capture_duration}",
            "-w", output_file
        ]
        try:
            subprocess.run(capture_command)
            print(f"File saved: {output_file}")
            print("!!!   successful   !!!")
            return output_file
        except subprocess.CalledProcessError as e:
            print(f"Capture failed: {e}")
            return None

    @staticmethod
    def extract_devices(pcap_file):
        devices = set()
        packets = rdpcap(pcap_file)

        for packet in packets:
            if packet.haslayer(Ether):
                src = packet[Ether].src
                dst = packet[Ether].dst
                # multicasting start with following
                if not (src.startswith("01:00:5e") or src.startswith("33:33") or src == "ff:ff:ff:ff:ff:ff"):
                    devices.add(src)
                if not (dst.startswith("01:00:5e") or dst.startswith("33:33") or dst == "ff:ff:ff:ff:ff:ff"):
                    devices.add(dst)

        return devices

    @staticmethod
    def save_to_csv(devices, csv_file):
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Device MAC Address"])
            for device in devices:
                writer.writerow([device])

        print(f"Devices information saved to: {csv_file}")

    def capture_and_extract(self):
        pcap_file = self.run_capture()
        if pcap_file:
            devices = self.extract_devices(pcap_file)
            csv_file = f"{self.output_folder}/devices.csv"
            self.save_to_csv(devices, csv_file)


wireshark_manager = WireSharkManager("wlp2s0", 12, "/home/ardafa/Documents/Wireshark_Data/Home")
wireshark_manager.capture_and_extract()
