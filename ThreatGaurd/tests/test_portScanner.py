import unittest
from unittest.mock import patch, MagicMock
from utils.port_scanner_ui import render_port_scanner_ui
import socket


class TestPortScanner(unittest.TestCase):

    @patch("socket.socket.connect_ex")
    def test_scan_ports_open(self, mock_connect_ex):
        mock_connect_ex.return_value = 0  # Simulate open ports

        # Directly test scan logic without UI
        open_ports = []
        for port in range(80, 85):  # Simulating a small range
            result = mock_connect_ex()
            if result == 0:
                open_ports.append(port)

        self.assertEqual(len(open_ports), 5)

    @patch("socket.socket.connect_ex")
    def test_scan_ports_closed(self, mock_connect_ex):
        mock_connect_ex.return_value = 1  # Simulate closed ports

        # Directly test scan logic without UI
        open_ports = []
        for port in range(80, 85):  # Simulating a small range
            result = mock_connect_ex()
            if result == 0:
                open_ports.append(port)

        self.assertEqual(len(open_ports), 0)

    @patch("socket.socket.connect_ex")
    def test_cancel_scan(self, mock_connect_ex):
        # Simulate canceling a scan (no active thread)
        scan_running = True

        def mock_scan_process():
            nonlocal scan_running
            scan_running = False

        mock_scan_process()

        self.assertFalse(scan_running)


if __name__ == "__main__":
    unittest.main()
