import unittest
from unittest.mock import patch, MagicMock
from utils.traffic_monitor import TrafficMonitor


class TestTrafficMonitor(unittest.TestCase):

    @patch("scapy.all.sniff")
    def test_start_and_stop_capture(self, mock_sniff):
        output_box = MagicMock()
        summary_label = MagicMock()

        monitor = TrafficMonitor(output_box, summary_label, username="TestUser")

        # Start capture (simulated)
        monitor.start_capture()
        self.assertTrue(monitor.capturing_flag["running"])

        # Stop capture
        monitor.stop_capture()
        self.assertFalse(monitor.capturing_flag["running"])

    def test_clear_output(self):
        output_box = MagicMock()
        summary_label = MagicMock()

        monitor = TrafficMonitor(output_box, summary_label)

        # Simulate adding packets
        monitor.captured_packets.append("Packet 1")
        monitor.protocol_counts["TCP"] = 5

        # Clear output
        monitor.clear_output()

        self.assertEqual(len(monitor.captured_packets), 0)
        self.assertEqual(monitor.protocol_counts["TCP"], 0)

    @patch("utils.traffic_monitor.wrpcap")
    def test_save_pcap(self, mock_wrpcap):
        output_box = MagicMock()
        summary_label = MagicMock()

        monitor = TrafficMonitor(output_box, summary_label)

        # Simulate captured packets
        monitor.captured_packets = ["Packet 1", "Packet 2"]

        # Save as PCAP (no actual file saved)
        monitor.save_pcap()

        mock_wrpcap.assert_called_once()  # Ensure PCAP save was attempted


if __name__ == "__main__":
    unittest.main()
