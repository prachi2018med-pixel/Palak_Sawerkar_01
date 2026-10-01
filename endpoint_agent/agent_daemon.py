"""
CyberTrace AI — Endpoint Agent Daemon
Runs in the background on employee computers to stream telemetry
to the central SOC server and handle emergency containment commands.
"""
import time
import json
import logging
import argparse
import sys
import tkinter as tk
from tkinter import messagebox
import httpx
from endpoint_agent.collector import EndpointCollector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

class EndpointDaemon:
    def __init__(self, server_url: str = "http://localhost:8000", interval: int = 10):
        self.server_url = server_url.rstrip("/")
        self.interval = interval
        self.collector = EndpointCollector()
        self.is_isolated = False

    def send_telemetry(self) -> dict | None:
        """Collect local endpoint data and post to central SOC REST API."""
        payload = self.collector.build_telemetry_payload()
        url = f"{self.server_url}/api/agent/telemetry"

        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.post(url, json=payload)
                if response.status_code == 200:
                    res_data = response.json()
                    logging.info(f"Telemetry sent successfully. Status: {res_data.get('status')}")
                    
                    # Check if server instructed an emergency popup or isolation
                    self.handle_server_directives(res_data.get("directives", {}))
                    return res_data
                else:
                    logging.warning(f"Server returned HTTP {response.status_code}: {response.text}")
        except Exception as e:
            logging.error(f"Failed to connect to SOC server at {url}: {e}")
        return None

    def handle_server_directives(self, directives: dict):
        """Execute server-side authorized commands (Emergency alert, Isolation)."""
        if directives.get("trigger_emergency_alert"):
            alert_msg = directives.get("alert_message", "CRITICAL SECURITY WARNING: Suspicious activity detected on your workstation.")
            self.show_emergency_banner(alert_msg)

        if directives.get("isolate_host") and not self.is_isolated:
            logging.warning("RECEIVED HOST ISOLATION DIRECTIVE FROM SOC!")
            self.apply_network_isolation()

    def show_emergency_banner(self, message: str):
        """Display an emergency alert banner on employee desktop screen."""
        logging.info(f"Displaying Emergency GUI Banner: {message}")
        try:
            root = tk.Tk()
            root.title("⚠️ EMERGENCY SECURITY ALERT — SOC NOTICE")
            root.geometry("600x250")
            root.attributes("-topmost", True)
            root.configure(bg="#8B0000") # Dark Red

            label = tk.Label(
                root, 
                text="⚠️ SECURITY EMERGENCY DETECTED", 
                font=("Arial", 16, "bold"), 
                fg="white", 
                bg="#8B0000"
            )
            label.pack(pady=15)

            msg_label = tk.Label(
                root, 
                text=message, 
                font=("Arial", 11), 
                fg="white", 
                bg="#8B0000",
                wraplength=520,
                justify="center"
            )
            msg_label.pack(pady=10)

            btn = tk.Button(root, text="Acknowledge", command=root.destroy, bg="white", fg="black", font=("Arial", 10, "bold"))
            btn.pack(pady=15)

            root.mainloop()
        except Exception as e:
            logging.error(f"Failed to display GUI banner: {e}")

    def apply_network_isolation(self):
        """Isolate host from local network (Human-in-the-Loop requirement)."""
        self.is_isolated = True
        logging.warning(f"Host {self.collector.hostname} isolated from local network.")

    def run_forever(self):
        """Main loop sending telemetry every `interval` seconds."""
        logging.info(f"Starting Endpoint Agent Daemon [Host: {self.collector.hostname}]")
        logging.info(f"SOC Server Endpoint: {self.server_url} (Poll Interval: {self.interval}s)")

        while True:
            self.send_telemetry()
            time.sleep(self.interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberTrace AI Endpoint Agent Daemon")
    parser.add_argument("--server", default="http://localhost:8000", help="SOC Server URL")
    parser.add_argument("--interval", type=int, default=10, help="Polling interval in seconds")
    args = parser.parse_args()

    daemon = EndpointDaemon(server_url=args.server, interval=args.interval)
    daemon.run_forever()
