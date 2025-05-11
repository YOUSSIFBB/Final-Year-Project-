from scapy.all import sniff, wrpcap, TCP, UDP, ICMP
import threading
import time
import os
from utils.dashboard_ui import log_scan


class TrafficMonitor:

    def __init__(self, output_box, summary_label, username="Guest"):
        self.output_box = output_box
        self.summary_label = summary_label
        self.username = username
        self.capturing_flag = {"running": False}
        self.capture_thread = None
        self.captured_packets = []
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

    def _update_summary(self):
        self.summary_label.configure(
            text=(
                f"📊 Protocol Summary — "
                f"TCP: {self.protocol_counts['TCP']} | "
                f"UDP: {self.protocol_counts['UDP']} | "
                f"ICMP: {self.protocol_counts['ICMP']} | "
                f"Other: {self.protocol_counts['Other']}"
            )
        )

    def process_packet(self, pkt):
        if not self.capturing_flag["running"]:
            return

        self.captured_packets.append(pkt)
        summary = pkt.summary()

        if pkt.haslayer(TCP):
            tag = "tcp"
            self.protocol_counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            tag = "udp"
            self.protocol_counts["UDP"] += 1
        elif pkt.haslayer(ICMP):
            tag = "icmp"
            self.protocol_counts["ICMP"] += 1
        else:
            tag = "other"
            self.protocol_counts["Other"] += 1

        self.output_box.insert("end", summary + "\n", tag)
        self.output_box.see("end")
        self._update_summary()

    def start_capture(self):
        if self.capturing_flag["running"]:
            return

        self.output_box.insert("end", "🟢 Starting packet capture...\n")
        self.output_box.see("end")
        # Add to database start time
        log_scan(
            username=self.username,
            scan_type="Traffic",
            target="LiveCapture",
            result="Started",
        )
        self.captured_packets.clear()
        for k in self.protocol_counts:
            self.protocol_counts[k] = 0
        self._update_summary()

        self.capturing_flag["running"] = True

        def sniffer():
            sniff(
                prn=self.process_packet,
                store=False,
                stop_filter=lambda x: not self.capturing_flag["running"],
            )

        self.capture_thread = threading.Thread(target=sniffer, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        if self.capturing_flag["running"]:
            self.capturing_flag["running"] = False
            self.output_box.insert("end", "🛑 Stopped packet capture.\n")
            self.output_box.see("end")

    def save_pcap(self):
        if not self.captured_packets:
            self.output_box.insert("end", "⚠ No packets to save.\n")
            self.output_box.see("end")
            return

        self.output_box.insert("end", "💾 Saving capture to file...\n")
        self.output_box.see("end")

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        os.makedirs(downloads, exist_ok=True)
        file_path = os.path.join(downloads, f"capture_{timestamp}.pcap")

        wrpcap(file_path, self.captured_packets)

        self.output_box.insert("end", f"✅ Saved: {file_path}\n")
        self.output_box.see("end")

    def clear_output(self):
        self.output_box.delete("1.0", "end")
        self.captured_packets.clear()
        for k in self.protocol_counts:
            self.protocol_counts[k] = 0
        self._update_summary()
