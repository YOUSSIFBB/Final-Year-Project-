import unittest
import os
from utils.traffic_monitor import TrafficMonitor
from unittest.mock import MagicMock


class TestTrafficMonitor(unittest.TestCase):

    def setUp(self):
        # initialise a mock output box and summary label
        self.output_box = MagicMock()
        self.summary_label = MagicMock()
        self.monitor = TrafficMonitor(
            self.output_box, self.summary_label, username="TestUser"
        )

    def test_start_and_stop_capture(self):
        # start capture
        self.monitor.start_capture()
        self.assertTrue(
            self.monitor.capturing_flag["running"], "Capture should be running."
        )

        # stop capture
        self.monitor.stop_capture()
        self.assertFalse(
            self.monitor.capturing_flag["running"], "Capture should be stopped."
        )

    def test_clear_output(self):
        # Simulate captured packets
        self.monitor.captured_packets = ["Packet 1", "Packet 2"]
        self.monitor.protocol_counts["TCP"] = 5

        # Clear output
        self.monitor.clear_output()

        self.assertEqual(len(self.monitor.captured_packets), 0)
        self.assertEqual(self.monitor.protocol_counts.get("TCP", 0), 0)

    def test_save_pcap(self):
        # Simulate captured packets
        self.monitor.captured_packets = ["Packet 1", "Packet 2"]

        # Save as PCAP (simulated)
        saved_path = "assets/test_capture.pcap"
        self.monitor.save_pcap(saved_path)

        # Ensure the file is created
        self.assertTrue(os.path.exists(saved_path))

        # Clean up
        os.remove(saved_path)


if __name__ == "__main__":
    unittest.main()
