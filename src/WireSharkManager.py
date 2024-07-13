import subprocess


class WireSharkManager:
    def __init__(self, interface, capture_duration, output_folder):
        self.interface = interface
        self.capture_duration = capture_duration
        self.output_folder = output_folder

    def run_capture(self):
        # it could be saved as a csv, but it is not readable from human :D
        output_file = f"{self.output_folder}/results.csv"
        capture_command = [
            "tshark", "-i", self.interface,
            "-a", f"duration:{self.capture_duration}",
            "-w", output_file
        ]
        try:
            subprocess.run(capture_command)
            print(f"File saved: {output_file}")
            print("!!!   successful   !!!")
        except subprocess.CalledProcessError as e:
            print(f"Capture failed: {e}")


wireshark_manager = WireSharkManager("wlp2s0", 10, "/home/ardafa/Documents/Wireshark_Data/Home")
wireshark_manager.run_capture()
