import unittest
import socket


class TestPortScanner(unittest.TestCase):

    def test_scan_open_ports(self):
        open_ports = []

        # san a range of ports on localhost
        for port in range(80, 85):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("127.0.0.1", port))
                if result == 0:  # Port is open
                    open_ports.append(port)

        print("Open Ports Found:", open_ports)

        # no guarantee of any open ports, so we only check for type list
        self.assertIsInstance(open_ports, list)

    def test_scan_closed_ports(self):
        closed_ports = []

        # scan a range of ports on localhost machine
        for port in range(65530, 65535):  # Unlikely to be open
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(("127.0.0.1", port))
                if result != 0:  # closed
                    closed_ports.append(port)

        print("Closed Ports Found:", closed_ports)

        # should see some closed ports
        self.assertGreater(len(closed_ports), 0)


if __name__ == "__main__":
    unittest.main()
