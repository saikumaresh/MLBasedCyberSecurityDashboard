import sys
from FeatureExtractor import *
from KitNET.KitNET import KitNET
import pyximport
pyximport.install()

# MIT License
#
# Copyright (c) 2018 Yisroel mirsky
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

class Kitsune:
    def __init__(self, file_path, limit, max_autoencoder_size=10, FM_grace_period=None, AD_grace_period=10000, learning_rate=0.1, hidden_ratio=0.75):
        # Initialize packet feature extractor (AfterImage)
        self.FE = FE(file_path, limit)
        print(f"Feature Extractor initialized with file: {file_path} and limit: {limit}")

        # Initialize KitNET
        self.AnomDetector = KitNET(self.FE.get_num_features(), max_autoencoder_size, FM_grace_period, AD_grace_period, learning_rate, hidden_ratio)
        print(f"KitNET initialized with {self.FE.get_num_features()} features")

    def proc_next_packet(self):
        # Create feature vector
        x = self.FE.get_next_vector()
        if len(x) == 0:
            return -1  # Error or no packets left

        # Process KitNET
        return self.AnomDetector.process(x)  # Will train during the grace periods, then execute on all the rest.


def main():
    if len(sys.argv) < 3:
        print("Usage: python Kitsune.py <pcap_file> <limit>")
        sys.exit(1)

    file_path = sys.argv[1]
    limit = int(sys.argv[2])  # Limit on packets to process

    # Initialize Kitsune with the provided arguments
    kitsune = Kitsune(file_path, limit)

    # Process packets and log anomalies
    anomalies = 0
    packet_count = 0
    while True:
        result = kitsune.proc_next_packet()
        if result == -1:
            print("No more packets to process.")
            break
        elif result > 0:
            anomalies += 1
            print(f"Anomaly detected in packet {packet_count}")

        packet_count += 1

    print(f"Processing complete. Total packets: {packet_count}, Anomalies detected: {anomalies}")


if __name__ == "__main__":
    main()
