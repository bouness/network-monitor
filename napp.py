import csv
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import psutil
from PySide6.QtCore import (
    QSettings,
    QSize,
    QStandardPaths,
    Qt,
    QThread,
    QTimer,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QDesktopServices,
    QFont,
    QIcon,
    QPainter,
    QPixmap,
)

# PySide6 imports
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

# Optional sound alert support
if platform.system() == "Windows":
    import winsound
else:
    # Fallback for other platforms
    winsound = None

from version import __version__

# Configuration constants
DEFAULT_CONFIG = {
    "refresh_interval": 1,
    "enable_alerts": True,
    "enable_sound": True,
    "start_minimized": False,
    "auto_start": False,
    "log_to_file": True,
    "max_log_entries": 1000,
    "window_geometry": None,
    "window_state": None,
    "auto_export": False,
    "export_interval": 60,
    "notify_new_ip": True,
    "notify_microsoft": False,
    "max_table_rows": 10000,
}

WHITELIST_APPS = {
    "firefox.exe",
    "chrome.exe",
    "brave.exe",
    "msedge.exe",
    "vivaldi.exe",
    "explorer.exe",
    "svchost.exe",
    "taskhost.exe",
    "dwm.exe",
    "ctfmon.exe",
}

MICROSOFT_SAFE_PROCS = {
    "svchost.exe",
    "explorer.exe",
    "onenote.exe",
    "onedrive.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "csrss.exe",
    "smss.exe",
}

MICROSOFT_KEYWORDS = [
    "microsoft",
    "windows",
    "azure",
    "office",
    "live.com",
    "outlook",
    "onedrive",
    "bing",
    "msedge",
    "msn",
    "xbox",
]

COLORS = {
    "new_ip": QColor(255, 87, 87),  # Red for new IPs
    "microsoft": QColor(100, 149, 237),  # Blue for Microsoft
    "external": QColor(255, 193, 7),  # Yellow for external
    "lan": QColor(56, 142, 60),  # Green for LAN
    "closed": QColor(120, 120, 120),  # Gray for closed
    "warning": QColor(255, 152, 0),  # Orange for warnings
    "success": QColor(76, 175, 80),  # Green for success
}


def resource_path(relative_path):
    """Get path relative to the executable or script."""
    if getattr(sys, "frozen", False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


SOUND_ALERT = resource_path("assets/notification.wav")


class AppPaths:
    """Handle all application paths for proper Windows deployment"""

    @staticmethod
    def get_app_data_dir() -> Path:
        """Get writable app data directory"""
        if platform.system() == "Windows":
            # Use AppData/Local for writable storage
            app_data = os.getenv(
                "LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local")
            )
            app_dir = Path(app_data) / "NetworkMonitor"
        else:
            # Use standard paths for other OS
            app_dir = Path(
                QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)
            )

        app_dir.mkdir(parents=True, exist_ok=True)
        return app_dir

    @staticmethod
    def get_logs_dir() -> Path:
        """Get logs directory"""
        logs_dir = AppPaths.get_app_data_dir() / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        return logs_dir

    @staticmethod
    def get_exports_dir() -> Path:
        """Get exports directory"""
        exports_dir = AppPaths.get_app_data_dir() / "exports"
        exports_dir.mkdir(parents=True, exist_ok=True)
        return exports_dir

    @staticmethod
    def get_firewall_dir() -> Path:
        """Get firewall rules directory"""
        firewall_dir = AppPaths.get_app_data_dir() / "firewall_rules"
        firewall_dir.mkdir(parents=True, exist_ok=True)
        return firewall_dir

    @staticmethod
    def get_seen_ips_file() -> Path:
        """Get seen IPs file path"""
        return AppPaths.get_app_data_dir() / "seen_ips.json"

    @staticmethod
    def get_log_file() -> Path:
        """Get log file path"""
        return AppPaths.get_logs_dir() / "network_monitor.log"

    @staticmethod
    def get_firewall_suggestions_file() -> Path:
        """Get firewall suggestions file path"""
        return AppPaths.get_firewall_dir() / "suggestions.txt"

    @staticmethod
    def get_auto_export_file(timestamp: str = None) -> Path:
        """Get auto export file path"""
        if not timestamp:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return AppPaths.get_exports_dir() / f"auto_export_{timestamp}.json"

    @staticmethod
    def ensure_directories():
        """Create all necessary directories"""
        directories = [
            AppPaths.get_app_data_dir(),
            AppPaths.get_logs_dir(),
            AppPaths.get_exports_dir(),
            AppPaths.get_firewall_dir(),
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)


class MonitorThread(QThread):
    """Thread for monitoring network connections"""

    connection_opened = Signal(dict)
    connection_closed = Signal(tuple)
    new_ip_alert = Signal(dict)
    status_update = Signal(str)
    error_occurred = Signal(str)
    stats_updated = Signal(dict)

    def __init__(self):
        super().__init__()
        self.running = False
        self.refresh_interval = 1
        self.enable_alerts = True
        self.enable_sound = True
        self.seen_ips = set()
        self.previous_connections = {}
        self.seen_rules = set()
        self.error_count = 0
        self.max_errors = 10

        # Load saved IPs
        self.load_seen_ips()

    def load_seen_ips(self):
        """Load previously seen IPs from file"""
        try:
            ip_file = AppPaths.get_seen_ips_file()
            if ip_file.exists():
                with open(ip_file, "r") as f:
                    self.seen_ips = set(json.load(f))
        except Exception as e:
            print(f"Error loading IPs: {e}")
            self.seen_ips = set()

    def save_seen_ips(self):
        """Save seen IPs to file"""
        try:
            with open(AppPaths.get_seen_ips_file(), "w") as f:
                json.dump(list(self.seen_ips), f, indent=2)
        except Exception as e:
            self.error_occurred.emit(f"Error saving IPs: {e}")

    def resolve_ip(self, ip: str) -> str:
        """Resolve IP to hostname with timeout"""
        try:
            socket.setdefaulttimeout(1)
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.timeout):
            return "Unknown"
        except Exception:
            return "Unknown"

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def is_microsoft(self, text: str) -> bool:
        """Check if hostname contains Microsoft keywords"""
        if not text or text == "Unknown":
            return False
        text = text.lower()
        return any(k in text for k in MICROSOFT_KEYWORDS)

    def snapshot_connections(self) -> Dict:
        """Take snapshot of current connections"""
        conns = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.raddr:
                    continue

                try:
                    proc = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc = "Unknown"

                # Get process info
                try:
                    process = psutil.Process(c.pid)
                    exe_path = process.exe()
                    cmdline = (
                        " ".join(process.cmdline()[:3])
                        if process.cmdline()
                        else ""
                    )
                    create_time = datetime.fromtimestamp(process.create_time())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    exe_path = "Unknown"
                    cmdline = ""
                    create_time = datetime.now()

                key = (
                    proc,
                    c.laddr.ip,
                    c.laddr.port,
                    c.raddr.ip,
                    c.raddr.port,
                )
                conns[key] = {
                    "status": c.status,
                    "exe_path": exe_path,
                    "cmdline": cmdline,
                    "pid": c.pid,
                    "create_time": create_time,
                }
        except Exception as e:
            self.error_count += 1
            if self.error_count <= self.max_errors:
                self.error_occurred.emit(f"Snapshot error: {str(e)}")

        return conns

    def find_program_path(self, proc: str) -> str:
        """Find executable path for process"""
        try:
            for p in psutil.process_iter(["name", "exe"]):
                if p.info["name"] == proc and p.info["exe"]:
                    return p.info["exe"]
        except Exception:
            pass
        return f"C:\\Path\\To\\{proc}"  # fallback

    def run(self):
        """Main monitoring loop"""
        self.running = True
        self.previous_connections = self.snapshot_connections()

        # Create timestamped batch file in firewall directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.bat_file = (
            AppPaths.get_firewall_dir()
            / f"apply_firewall_blocks_{timestamp}.bat"
        )

        # Initialize batch file
        try:
            with open(self.bat_file, "w", encoding="utf-8") as bat:
                bat.write("@echo off\n")
                bat.write(
                    "REM Run this file as Administrator to apply firewall rules\n"
                )
                bat.write("REM Created by Network Monitor\n")
                bat.write("REM File: {}\n\n".format(self.bat_file))
                bat.write("echo Applying firewall rules...\n")
                bat.write("echo.\n")
        except Exception as e:
            self.error_occurred.emit(f"Error creating batch file: {e}")

        self.status_update.emit("Monitoring started...")
        start_time = time.time()

        try:
            while self.running:
                loop_start = time.time()

                current = self.snapshot_connections()

                # Check for new connections
                new_connections = (
                    current.keys() - self.previous_connections.keys()
                )
                for key in new_connections:
                    proc, lip, lp, rip, rp = key
                    conn_info = current[key]

                    # Skip whitelisted apps
                    skip_alert = (
                        proc.lower() in WHITELIST_APPS
                        or proc.lower() in MICROSOFT_SAFE_PROCS
                    )

                    # Determine category
                    if self.is_private_ip(rip):
                        category = "LAN"
                        hostname = "Local"
                    else:
                        hostname = self.resolve_ip(rip)
                        if self.is_microsoft(hostname):
                            category = "Microsoft"
                        else:
                            category = "External"

                    # Check if new IP
                    is_new_ip = False
                    if (
                        not self.is_private_ip(rip)
                        and rip not in self.seen_ips
                    ):
                        self.seen_ips.add(rip)
                        is_new_ip = True
                        category += " | NEW"

                        if self.enable_alerts and not skip_alert:
                            alert_data = {
                                "process": proc,
                                "ip": rip,
                                "port": rp,
                                "hostname": hostname,
                                "category": category,
                                "local_ip": lip,
                                "local_port": lp,
                                "pid": conn_info["pid"],
                            }
                            self.new_ip_alert.emit(alert_data)

                            # Generate firewall suggestion
                            self.generate_firewall_rule(proc, rip)

                    # Emit connection opened signal
                    conn_data = {
                        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                        "process": proc,
                        "local_ip": lip,
                        "local_port": lp,
                        "remote_ip": rip,
                        "remote_port": rp,
                        "status": conn_info["status"],
                        "category": category,
                        "hostname": hostname,
                        "pid": conn_info["pid"],
                        "exe_path": conn_info["exe_path"],
                        "cmdline": conn_info["cmdline"],
                        "new_ip": is_new_ip,
                        "create_time": conn_info["create_time"].strftime(
                            "%H:%M:%S"
                        ),
                    }
                    self.connection_opened.emit(conn_data)

                # Check for closed connections
                closed_connections = (
                    self.previous_connections.keys() - current.keys()
                )
                for key in closed_connections:
                    self.connection_closed.emit(key)

                self.previous_connections = current

                # Emit stats periodically
                if time.time() - start_time >= 5:  # Every 5 seconds
                    stats = {
                        "active_connections": len(current),
                        "new_connections": len(new_connections),
                        "closed_connections": len(closed_connections),
                        "unique_ips": len(self.seen_ips),
                    }
                    self.stats_updated.emit(stats)
                    start_time = time.time()

                # Save IPs every minute
                if int(time.time()) % 60 == 0:
                    self.save_seen_ips()

                # Calculate sleep time to maintain consistent interval
                loop_time = time.time() - loop_start
                sleep_time = max(0.1, self.refresh_interval - loop_time)
                time.sleep(sleep_time)

        except Exception as e:
            self.status_update.emit(f"Critical error: {str(e)}")
            self.error_occurred.emit(f"Monitoring loop error: {e}")
        finally:
            self.save_seen_ips()

    def generate_firewall_rule(self, proc: str, ip: str):
        """Generate firewall block rule"""
        try:
            program_path = self.find_program_path(proc)
            rule_name = f"Block_{proc}_{ip.replace('.', '_')}"
            netsh_command = (
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir=out action=block program="{program_path}" remoteip={ip}'
            )

            if netsh_command not in self.seen_rules:
                self.seen_rules.add(netsh_command)

                # Append to batch file
                with open(self.bat_file, "a", encoding="utf-8") as bat:
                    bat.write(netsh_command + "\n")

                # Log to firewall suggestions
                with open(
                    AppPaths.get_firewall_suggestions_file(),
                    "a",
                    encoding="utf-8",
                ) as f:
                    f.write(f"[{datetime.now()}] {proc} -> {ip}\n")
                    f.write(f"{netsh_command}\n\n")
        except Exception as e:
            self.error_occurred.emit(f"Error generating firewall rule: {e}")

    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        if self.isRunning():
            self.quit()
            self.wait(2000)  # Wait up to 2 seconds


class ConnectionTable(QTableWidget):
    """Custom table for displaying connections"""

    def __init__(self, max_rows: int = 10000):
        super().__init__()
        self.max_rows = max_rows
        self.setColumnCount(9)
        self.setHorizontalHeaderLabels(
            [
                "Time",
                "Process",
                "Remote IP",
                "Port",
                "Hostname",
                "Status",
                "Category",
                "PID",
                "Process Start",
            ]
        )

        # Style the table
        self.setAlternatingRowColors(True)
        self.horizontalHeader().setStretchLastSection(False)
        self.setSortingEnabled(True)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.ExtendedSelection)

        # Set column widths
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Process
        header.setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )  # Remote IP
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Port
        header.setSectionResizeMode(4, QHeaderView.Interactive)  # Hostname
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(6, QHeaderView.Interactive)  # Category
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)  # PID
        header.setSectionResizeMode(
            8, QHeaderView.ResizeToContents
        )  # Process Start

        # Set initial column widths
        self.setColumnWidth(0, 80)  # Time
        self.setColumnWidth(1, 150)  # Process
        self.setColumnWidth(2, 120)  # Remote IP
        self.setColumnWidth(3, 60)  # Port
        self.setColumnWidth(4, 200)  # Hostname
        self.setColumnWidth(5, 80)  # Status
        self.setColumnWidth(6, 120)  # Category
        self.setColumnWidth(7, 60)  # PID
        self.setColumnWidth(8, 80)  # Process Start

        # Enable context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)

        # Store connection data by row
        self.connection_data = {}

    def add_connection(self, conn_data: dict):
        """Add a new connection to the table"""
        # Limit table size
        if self.rowCount() >= self.max_rows:
            self.removeRow(0)

        row = self.rowCount()
        self.insertRow(row)

        # Determine color based on category
        color = None
        if conn_data.get("new_ip", False):
            color = COLORS["new_ip"]
        elif "Microsoft" in conn_data["category"]:
            color = COLORS["microsoft"]
        elif "LAN" in conn_data["category"]:
            color = COLORS["lan"]
        elif "External" in conn_data["category"]:
            color = COLORS["external"]

        items = [
            QTableWidgetItem(conn_data["time"]),
            QTableWidgetItem(conn_data["process"]),
            QTableWidgetItem(conn_data["remote_ip"]),
            QTableWidgetItem(str(conn_data["remote_port"])),
            QTableWidgetItem(conn_data["hostname"]),
            QTableWidgetItem(conn_data["status"]),
            QTableWidgetItem(conn_data["category"]),
            QTableWidgetItem(str(conn_data["pid"])),
            QTableWidgetItem(conn_data.get("create_time", "N/A")),
        ]

        for i, item in enumerate(items):
            if color:
                item.setBackground(color)
                # Set text color for better contrast
                if color == COLORS["new_ip"]:
                    item.setForeground(QBrush(Qt.white))
            item.setToolTip(self.get_tooltip(conn_data, i))
            self.setItem(row, i, item)

        # Store connection data
        self.connection_data[row] = conn_data

        # Scroll to new row if not at bottom
        if row > self.rowCount() - 10:
            self.scrollToBottom()

    def get_tooltip(self, conn_data: dict, column: int) -> str:
        """Get tooltip for a column"""
        tooltips = {
            0: f"Connection time: {conn_data['time']}",
            1: f"Process: {conn_data['process']}\nPath: {conn_data.get('exe_path', 'Unknown')}",
            2: f"Remote IP: {conn_data['remote_ip']}\nLocal IP: {conn_data['local_ip']}",
            3: f"Remote port: {conn_data['remote_port']}\nLocal port: {conn_data['local_port']}",
            4: f"Hostname: {conn_data['hostname']}",
            5: f"Status: {conn_data['status']}",
            6: f"Category: {conn_data['category']}",
            7: f"PID: {conn_data['pid']}",
            8: f"Process started: {conn_data.get('create_time', 'N/A')}",
        }
        return tooltips.get(column, "")

    def get_selected_connections(self) -> List[dict]:
        """Get data for selected connections"""
        selected = []
        for row in range(self.rowCount()):
            if self.item(row, 0) and self.item(row, 0).isSelected():
                selected.append(self.connection_data.get(row, {}))
        return selected


class StatisticsWidget(QWidget):
    """Widget for displaying statistics"""

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        # Create a scroll area for the entire statistics widget
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # Main container widget
        container = QWidget()
        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(10)

        # Summary statistics group - FIXED HEIGHT
        summary_group = QGroupBox("Summary Statistics")
        summary_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        summary_layout = QGridLayout()
        summary_layout.setContentsMargins(10, 15, 10, 15)
        summary_layout.setSpacing(5)

        self.labels = {}
        metrics = [
            ("Session Duration", "session_duration"),
            ("Total Connections", "total_connections"),
            ("Active Connections", "active_connections"),
            ("Peak Connections", "peak_connections"),
            ("Connections/Min", "connections_per_min"),
            ("Unique Processes", "unique_processes"),
            ("Unique IPs", "unique_ips"),
            ("New IP Alerts", "new_ip_alerts"),
            ("LAN Connections", "lan_connections"),
            ("Microsoft Connections", "microsoft_connections"),
            ("External Connections", "external_connections"),
        ]

        # Create 2-column layout for metrics
        for i, (label_text, key) in enumerate(metrics):
            row = i // 2
            col = (i % 2) * 2

            label = QLabel(label_text + ":")
            label.setStyleSheet("font-weight: bold;")

            value_label = QLabel("0")
            value_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
            value_label.setMinimumWidth(80)

            summary_layout.addWidget(label, row, col)
            summary_layout.addWidget(value_label, row, col + 1)
            self.labels[key] = value_label

        # Add stretch to make columns equal width
        summary_layout.setColumnStretch(0, 1)
        summary_layout.setColumnStretch(2, 1)

        summary_group.setLayout(summary_layout)
        main_layout.addWidget(summary_group)

        # Connection Timeline group - FIXED HEIGHT
        timeline_group = QGroupBox("Connection Timeline")
        timeline_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        timeline_layout = QVBoxLayout()
        timeline_layout.setContentsMargins(10, 10, 10, 10)

        self.chart_label = QLabel(
            "Hourly connection distribution will appear here"
        )
        self.chart_label.setAlignment(Qt.AlignCenter)
        self.chart_label.setWordWrap(True)
        self.chart_label.setMinimumHeight(80)
        timeline_layout.addWidget(self.chart_label)

        timeline_group.setLayout(timeline_layout)
        main_layout.addWidget(timeline_group)

        # Top Lists group - EXPANDING
        top_group = QGroupBox("Top Lists")
        top_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        top_layout = QHBoxLayout()
        top_layout.setContentsMargins(10, 10, 10, 10)
        top_layout.setSpacing(10)

        # Top processes
        proc_group = QGroupBox("Top Processes")
        proc_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        proc_layout = QVBoxLayout()
        self.top_processes = QTextEdit()
        self.top_processes.setReadOnly(True)
        self.top_processes.setFont(QFont("Consolas", 9))
        self.top_processes.setLineWrapMode(QTextEdit.NoWrap)
        proc_layout.addWidget(self.top_processes)
        proc_group.setLayout(proc_layout)
        top_layout.addWidget(proc_group)

        # Top destinations
        dest_group = QGroupBox("Top Destinations")
        dest_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        dest_layout = QVBoxLayout()
        self.top_destinations = QTextEdit()
        self.top_destinations.setReadOnly(True)
        self.top_destinations.setFont(QFont("Consolas", 9))
        self.top_destinations.setLineWrapMode(QTextEdit.NoWrap)
        dest_layout.addWidget(self.top_destinations)
        dest_group.setLayout(dest_layout)
        top_layout.addWidget(dest_group)

        # Set stretch factors so both sides expand equally
        top_layout.setStretch(0, 1)
        top_layout.setStretch(1, 1)

        top_group.setLayout(top_layout)
        main_layout.addWidget(top_group)

        # Add stretch at the bottom
        main_layout.addStretch(1)

        # Set the container as the scroll area widget
        scroll_area.setWidget(container)

        # Set main layout for StatisticsWidget
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll_area)


class NetworkMonitorGUI(QMainWindow):
    """Main GUI window"""

    def __init__(self):
        super().__init__()
        self.monitor_thread = None
        self.settings = QSettings("NetworkMonitor", "App")
        self.load_settings()

        # Ensure all directories exist
        AppPaths.ensure_directories()

        self.init_ui()
        self.init_tray()
        self.init_menu()
        self.init_statistics()

        # Track if we're shutting down
        self.shutting_down = False

        # Log startup
        self.log_message(
            f"Application started. Data directory: {AppPaths.get_app_data_dir()}",
            "info",
        )

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle(f"Network Monitor {__version__}")
        self.setMinimumSize(1000, 600)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)

        # Toolbar
        self.init_toolbar()
        main_layout.addWidget(self.toolbar)

        # Control panel
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)

        # Main content area with splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(5)

        # Left side - Connections table
        left_widget = QWidget()
        left_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(5)

        # Search and filter bar
        filter_widget = QWidget()
        filter_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        filter_layout = QHBoxLayout(filter_widget)
        filter_layout.setContentsMargins(5, 5, 5, 5)
        filter_layout.addWidget(QLabel("Filter:"))

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText(
            "Filter by process, IP, hostname..."
        )
        self.filter_input.textChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_input, 1)  # Stretch factor 1

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(
            ["All", "New IPs", "Microsoft", "External", "LAN"]
        )
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_combo)

        clear_filter_btn = QPushButton("Clear Filter")
        clear_filter_btn.clicked.connect(self.clear_filter)
        filter_layout.addWidget(clear_filter_btn)

        left_layout.addWidget(filter_widget)

        self.connection_table = ConnectionTable(
            max_rows=self.settings.value("max_table_rows", 10000, type=int)
        )
        self.connection_table.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        self.connection_table.customContextMenuRequested.connect(
            self.show_context_menu
        )
        left_layout.addWidget(self.connection_table, 1)  # Stretch factor 1

        splitter.addWidget(left_widget)

        # Right side - Statistics
        self.stats_widget = StatisticsWidget()
        self.stats_widget.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        splitter.addWidget(self.stats_widget)

        # Set initial splitter sizes (70% left, 30% right)
        splitter.setSizes([700, 300])
        main_layout.addWidget(splitter, 1)  # Stretch factor 1

        # Tab widget for log and details
        tabs = QTabWidget()
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        tabs.setMaximumHeight(250)

        # Log tab
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        log_layout.setContentsMargins(5, 5, 5, 5)
        log_layout.setSpacing(5)

        # Log controls
        log_controls = QHBoxLayout()
        log_controls.setContentsMargins(0, 0, 0, 0)

        self.log_clear_btn = QPushButton("Clear Log")
        self.log_clear_btn.clicked.connect(self.clear_log)
        log_controls.addWidget(self.log_clear_btn)

        self.log_pause_btn = QPushButton("Pause Updates")
        self.log_pause_btn.setCheckable(True)
        self.log_pause_btn.toggled.connect(self.toggle_log_updates)
        log_controls.addWidget(self.log_pause_btn)

        self.log_autoscroll = QCheckBox("Auto-scroll")
        self.log_autoscroll.setChecked(True)
        log_controls.addWidget(self.log_autoscroll)
        log_controls.addStretch()

        log_layout.addLayout(log_controls)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(
            QFont(
                "Consolas" if platform.system() == "Windows" else "Monospace",
                9,
            )
        )
        self.log_text.setMaximumHeight(150)
        log_layout.addWidget(self.log_text)

        tabs.addTab(log_tab, "Event Log")

        # Details tab
        details_tab = QWidget()
        details_layout = QVBoxLayout(details_tab)
        details_layout.setContentsMargins(5, 5, 5, 5)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Consolas", 10))
        self.details_text.setMaximumHeight(150)
        details_layout.addWidget(self.details_text)

        tabs.addTab(details_tab, "Connection Details")

        main_layout.addWidget(tabs)

        # Status bar
        self.init_status_bar()

        # Load saved settings
        self.apply_settings()

        # Auto-save timer
        self.autosave_timer = QTimer()
        self.autosave_timer.timeout.connect(self.autosave)
        self.autosave_timer.start(60000)  # Auto-save every minute

        # Auto-export if enabled
        if self.settings.value("auto_export", False, type=bool):
            export_interval = (
                self.settings.value("export_interval", 60, type=int) * 60000
            )
            self.export_timer = QTimer()
            self.export_timer.timeout.connect(self.auto_export)
            self.export_timer.start(export_interval)

        # Statistics update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_statistics_display)
        self.stats_timer.start(2000)  # Update every 2 seconds

    def init_toolbar(self):
        """Initialize the toolbar"""
        self.toolbar = QToolBar()
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setMovable(False)
        self.addToolBar(self.toolbar)

        # Start/Stop action
        self.start_action = QAction("▶ Start Monitoring", self)
        self.start_action.triggered.connect(self.toggle_monitoring)
        self.toolbar.addAction(self.start_action)

        self.toolbar.addSeparator()

        # Export actions
        export_action = QAction("💾 Export Data", self)
        export_action.triggered.connect(self.export_data)
        self.toolbar.addAction(export_action)

        # Clear action
        clear_action = QAction("🗑️ Clear All", self)
        clear_action.triggered.connect(self.clear_all)
        self.toolbar.addAction(clear_action)

        self.toolbar.addSeparator()

        # Settings action
        settings_action = QAction("⚙️ Settings", self)
        settings_action.triggered.connect(self.show_settings)
        self.toolbar.addAction(settings_action)

        # Help action
        help_action = QAction("❓ Help", self)
        help_action.triggered.connect(self.show_help)
        self.toolbar.addAction(help_action)

        # Data directory button
        self.toolbar.addSeparator()
        data_dir_action = QAction("📁 Open Data Directory", self)
        data_dir_action.triggered.connect(self.open_data_directory)
        self.toolbar.addAction(data_dir_action)

    def init_status_bar(self):
        """Initialize the status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Status label
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)

        # Data directory label
        data_dir_label = QLabel(f"Data: {AppPaths.get_app_data_dir().name}")
        data_dir_label.setToolTip(str(AppPaths.get_app_data_dir()))
        self.status_bar.addWidget(data_dir_label)

        # Statistics labels
        self.connections_label = QLabel("Connections: 0")
        self.status_bar.addPermanentWidget(self.connections_label)

        self.ips_label = QLabel("Unique IPs: 0")
        self.status_bar.addPermanentWidget(self.ips_label)

        self.errors_label = QLabel("Errors: 0")
        self.status_bar.addPermanentWidget(self.errors_label)

        # Progress bar for operations
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(150)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def init_menu(self):
        """Initialize the menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        export_menu = file_menu.addMenu("&Export")
        export_csv_action = QAction("Export as CSV", self)
        export_csv_action.triggered.connect(
            lambda: self.export_data(format="csv")
        )
        export_menu.addAction(export_csv_action)

        export_json_action = QAction("Export as JSON", self)
        export_json_action.triggered.connect(
            lambda: self.export_data(format="json")
        )
        export_menu.addAction(export_json_action)

        file_menu.addSeparator()

        open_data_dir_action = QAction("Open Data Directory", self)
        open_data_dir_action.triggered.connect(self.open_data_directory)
        file_menu.addAction(open_data_dir_action)

        file_menu.addSeparator()

        exit_action = QAction("&Exit", self)
        exit_action.triggered.connect(self.quit_application)
        file_menu.addAction(exit_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        auto_scroll_action = QAction("Auto-scroll Log", self)
        auto_scroll_action.setCheckable(True)
        auto_scroll_action.setChecked(True)
        auto_scroll_action.triggered.connect(self.toggle_auto_scroll)
        view_menu.addAction(auto_scroll_action)

        # Tools menu
        tools_menu = menubar.addMenu("&Tools")

        flush_dns_action = QAction("Flush DNS Cache", self)
        flush_dns_action.triggered.connect(self.flush_dns)
        tools_menu.addAction(flush_dns_action)

        show_firewall_action = QAction("Show Firewall Rules", self)
        show_firewall_action.triggered.connect(self.show_firewall_rules)
        tools_menu.addAction(show_firewall_action)

        open_logs_action = QAction("Open Logs Directory", self)
        open_logs_action.triggered.connect(self.open_logs_directory)
        tools_menu.addAction(open_logs_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        docs_action = QAction("&Documentation", self)
        docs_action.triggered.connect(self.show_documentation)
        help_menu.addAction(docs_action)

    def create_control_panel(self) -> QWidget:
        """Create the control panel with buttons and settings"""
        panel = QGroupBox("Controls")
        panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Monitoring controls
        monitor_group = QGroupBox("Monitoring")
        monitor_group.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        monitor_layout = QHBoxLayout(monitor_group)
        monitor_layout.setContentsMargins(10, 5, 10, 5)

        monitor_layout.addWidget(QLabel("Refresh:"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1, 60)
        self.interval_spin.setSuffix(" sec")
        self.interval_spin.setValue(
            self.settings.value("refresh_interval", 1, type=int)
        )
        self.interval_spin.setMaximumWidth(80)
        monitor_layout.addWidget(self.interval_spin)

        layout.addWidget(monitor_group)

        # Alert controls
        alert_group = QGroupBox("Alerts")
        alert_group.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        alert_layout = QHBoxLayout(alert_group)
        alert_layout.setContentsMargins(10, 5, 10, 5)

        self.alerts_check = QCheckBox("Enable Alerts")
        self.alerts_check.setChecked(
            self.settings.value("enable_alerts", True, type=bool)
        )
        alert_layout.addWidget(self.alerts_check)

        self.sound_check = QCheckBox("Enable Sound")
        self.sound_check.setChecked(
            self.settings.value("enable_sound", True, type=bool)
        )
        alert_layout.addWidget(self.sound_check)

        self.notify_new_ip = QCheckBox("Notify New IPs")
        self.notify_new_ip.setChecked(
            self.settings.value("notify_new_ip", True, type=bool)
        )
        alert_layout.addWidget(self.notify_new_ip)

        layout.addWidget(alert_group)

        # Log controls
        log_group = QGroupBox("Logging")
        log_group.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        log_layout = QHBoxLayout(log_group)
        log_layout.setContentsMargins(10, 5, 10, 5)

        self.log_check = QCheckBox("Log to File")
        self.log_check.setChecked(
            self.settings.value("log_to_file", True, type=bool)
        )
        log_layout.addWidget(self.log_check)

        self.auto_export_check = QCheckBox("Auto Export")
        self.auto_export_check.setChecked(
            self.settings.value("auto_export", False, type=bool)
        )
        log_layout.addWidget(self.auto_export_check)

        layout.addWidget(log_group)

        # Action buttons
        button_group = QWidget()
        button_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        button_layout = QHBoxLayout(button_group)
        button_layout.setContentsMargins(0, 0, 0, 0)

        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.clicked.connect(self.toggle_monitoring)
        self.start_btn.setMinimumWidth(120)
        self.start_btn.setStyleSheet(
            """
            QPushButton {
                font-weight: bold;
                padding: 6px 12px;
                border-radius: 4px;
                background-color: #4CAF50;
                color: white;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """
        )
        button_layout.addWidget(self.start_btn)

        clear_btn = QPushButton("Clear Data")
        clear_btn.clicked.connect(self.clear_all)
        clear_btn.setMinimumWidth(80)
        button_layout.addWidget(clear_btn)

        export_btn = QPushButton("Export Now")
        export_btn.clicked.connect(self.export_data)
        export_btn.setMinimumWidth(80)
        button_layout.addWidget(export_btn)

        layout.addWidget(button_group)

        return panel

    def init_tray(self):
        """Initialize system tray icon"""
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = QSystemTrayIcon(self)

            # Create a simple icon
            pixmap = QPixmap(64, 64)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(QColor(42, 130, 218))
            painter.drawEllipse(8, 8, 48, 48)
            painter.setPen(Qt.white)
            painter.setFont(QFont("Arial", 24))
            painter.drawText(pixmap.rect(), Qt.AlignCenter, "N")
            painter.end()

            self.tray_icon.setIcon(QIcon(pixmap))

            tray_menu = QMenu()

            show_action = QAction("Show", self)
            show_action.triggered.connect(self.show_normal)
            tray_menu.addAction(show_action)

            toggle_monitor_action = QAction("Start/Stop Monitoring", self)
            toggle_monitor_action.triggered.connect(self.toggle_monitoring)
            tray_menu.addAction(toggle_monitor_action)

            tray_menu.addSeparator()

            open_data_dir_action = QAction("Open Data Directory", self)
            open_data_dir_action.triggered.connect(self.open_data_directory)
            tray_menu.addAction(open_data_dir_action)

            tray_menu.addSeparator()

            quit_action = QAction("Quit", self)
            quit_action.triggered.connect(self.quit_application)
            tray_menu.addAction(quit_action)

            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()
            self.tray_icon.setToolTip("Network Monitor")

            self.tray_icon.activated.connect(self.tray_activated)

            # Track if we're quitting via tray
            self.quitting_from_tray = False

    def init_statistics(self):
        """Initialize statistics tracking"""
        self.statistics = {
            "start_time": datetime.now(),
            "total_connections": 0,
            "active_connections": 0,
            "unique_processes": set(),
            "unique_ips": set(),
            "connections_by_type": Counter(),
            "connections_by_process": Counter(),
            "connections_by_ip": Counter(),
            "connections_by_hour": Counter(),
            "new_ip_alerts": 0,
            "lan_connections": 0,
            "external_connections": 0,
            "microsoft_connections": 0,
            "peak_connections": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connection_durations": [],
            "errors": 0,
        }

        # Connection tracking for duration calculation
        self.active_connection_times = {}

    def open_data_directory(self):
        """Open the data directory in file explorer"""
        try:
            data_dir = AppPaths.get_app_data_dir()
            if platform.system() == "Windows":
                os.startfile(data_dir)
            elif platform.system() == "Darwin":  # macOS
                subprocess.Popen(["open", data_dir])
            else:  # Linux
                subprocess.Popen(["xdg-open", data_dir])
            self.log_message(f"Opened data directory: {data_dir}", "info")
        except Exception as e:
            self.log_message(f"Failed to open data directory: {e}", "error")

    def open_logs_directory(self):
        """Open the logs directory in file explorer"""
        try:
            logs_dir = AppPaths.get_logs_dir()
            if platform.system() == "Windows":
                os.startfile(logs_dir)
            elif platform.system() == "Darwin":  # macOS
                subprocess.Popen(["open", logs_dir])
            else:  # Linux
                subprocess.Popen(["xdg-open", logs_dir])
            self.log_message(f"Opened logs directory: {logs_dir}", "info")
        except Exception as e:
            self.log_message(f"Failed to open logs directory: {e}", "error")

    def show_normal(self):
        """Show and restore window"""
        self.show()
        self.activateWindow()
        self.raise_()

    def quit_application(self):
        """Quit the application completely"""
        self.quitting_from_tray = True
        self.shutting_down = True
        self.close()

    def closeEvent(self, event):
        """Handle window close event"""
        # Set shutting down flag
        self.shutting_down = True

        # Stop timers first
        if hasattr(self, "stats_timer"):
            self.stats_timer.stop()
        if hasattr(self, "autosave_timer"):
            self.autosave_timer.stop()
        if hasattr(self, "export_timer"):
            self.export_timer.stop()

        # Save settings
        self.save_settings()

        # Stop monitoring thread
        self.stop_monitoring()

        # Check if we're quitting from tray or closing window
        if hasattr(self, "quitting_from_tray") and self.quitting_from_tray:
            # Quit completely
            QApplication.quit()
            event.accept()
        elif hasattr(self, "tray_icon") and self.tray_icon.isVisible():
            # Just hide to tray
            self.hide()
            self.tray_icon.showMessage(
                "Network Monitor",
                "Running in system tray. Right-click for options.",
                QSystemTrayIcon.Information,
                2000,
            )
            event.ignore()
        else:
            # No tray available, quit completely
            QApplication.quit()
            event.accept()

    def tray_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_normal()

    def toggle_monitoring(self):
        """Start or stop monitoring"""
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def start_monitoring(self):
        """Start the monitoring thread"""
        if self.monitor_thread and self.monitor_thread.isRunning():
            return

        self.monitor_thread = MonitorThread()
        self.monitor_thread.refresh_interval = self.interval_spin.value()
        self.monitor_thread.enable_alerts = self.alerts_check.isChecked()
        self.monitor_thread.enable_sound = self.sound_check.isChecked()

        # Connect signals
        self.monitor_thread.connection_opened.connect(
            self.on_connection_opened
        )
        self.monitor_thread.connection_closed.connect(
            self.on_connection_closed
        )
        self.monitor_thread.new_ip_alert.connect(self.on_new_ip_alert)
        self.monitor_thread.status_update.connect(self.status_label.setText)
        self.monitor_thread.error_occurred.connect(self.on_error)
        self.monitor_thread.stats_updated.connect(self.on_stats_updated)

        self.monitor_thread.start()

        # Update UI
        self.start_btn.setText("Stop Monitoring")
        self.start_btn.setStyleSheet(
            """
            QPushButton {
                font-weight: bold;
                padding: 6px 12px;
                border-radius: 4px;
                background-color: #d32f2f;
                color: white;
            }
            QPushButton:hover {
                background-color: #c62828;
            }
        """
        )
        self.start_action.setText("⏸ Stop Monitoring")

        self.log_message("Monitoring started", "info")
        self.status_label.setText("Monitoring active")

        # Update status bar
        self.connections_label.setText("Connections: 0")
        self.errors_label.setText("Errors: 0")

    def stop_monitoring(self):
        """Stop the monitoring thread"""
        if self.monitor_thread:
            self.monitor_thread.stop()
            self.monitor_thread = None

        # Update UI
        self.start_btn.setText("Start Monitoring")
        self.start_btn.setStyleSheet(
            """
            QPushButton {
                font-weight: bold;
                padding: 6px 12px;
                border-radius: 4px;
                background-color: #4CAF50;
                color: white;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """
        )
        self.start_action.setText("▶ Start Monitoring")

        self.log_message("Monitoring stopped", "info")
        self.status_label.setText("Monitoring stopped")

    def on_connection_opened(self, conn_data: dict):
        """Handle new connection"""
        if self.shutting_down:
            return

        # Update statistics
        self.update_statistics(conn_data)

        # Add to table
        self.connection_table.add_connection(conn_data)

        # Log the connection
        log_msg = (
            f"[{conn_data['time']}] {conn_data['process']} → "
            f"{conn_data['remote_ip']}:{conn_data['remote_port']} "
            f"({conn_data['hostname']}) - {conn_data['category']}"
        )
        self.log_message(log_msg, "connection")

        # Update details tab
        self.update_connection_details(conn_data)

        # Log to file if enabled
        if self.log_check.isChecked():
            try:
                with open(AppPaths.get_log_file(), "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now().isoformat()}: {log_msg}\n")
            except Exception as e:
                self.log_message(f"Error writing to log file: {e}", "error")

    def on_connection_closed(self, conn_key: tuple):
        """Handle closed connection"""
        if self.shutting_down:
            return

        proc, lip, lp, rip, rp = conn_key
        log_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {proc} → {rip}:{rp} - CLOSED"
        self.log_message(log_msg, "connection")

        # Update active connections count
        self.statistics["active_connections"] = max(
            0, self.statistics["active_connections"] - 1
        )

        # Calculate connection duration
        key = f"{proc}_{rip}_{rp}"
        if key in self.active_connection_times:
            duration = datetime.now() - self.active_connection_times[key]
            self.statistics["connection_durations"].append(duration.seconds)
            del self.active_connection_times[key]

    def on_new_ip_alert(self, alert_data: dict):
        """Handle new IP alert"""
        if self.shutting_down:
            return

        if not self.notify_new_ip.isChecked():
            return

        alert_msg = (
            f"🚨 NEW IP ALERT\n"
            f"Process: {alert_data['process']} (PID: {alert_data['pid']})\n"
            f"Remote: {alert_data['ip']}:{alert_data['port']}\n"
            f"Hostname: {alert_data['hostname']}\n"
            f"Category: {alert_data['category']}"
        )

        # Show tray notification
        if hasattr(self, "tray_icon") and self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                "New Network Connection Detected",
                f"{alert_data['process']} → {alert_data['ip']}",
                QSystemTrayIcon.Warning,
                5000,
            )

        # Play sound if enabled
        if self.sound_check.isChecked() and winsound:
            try:
                # winsound.Beep(1000, 300)
                winsound.PlaySound(
                    SOUND_ALERT, winsound.SND_FILENAME | winsound.SND_ASYNC
                )
            except Exception:
                pass

        self.log_message(alert_msg, "alert")

    def on_error(self, error_msg: str):
        """Handle error from monitor thread"""
        if self.shutting_down:
            return

        self.statistics["errors"] += 1
        self.errors_label.setText(f"Errors: {self.statistics['errors']}")
        self.log_message(f"Error: {error_msg}", "error")

    def on_stats_updated(self, stats: dict):
        """Update status bar with real-time stats"""
        if self.shutting_down:
            return

        self.connections_label.setText(
            f"Connections: {stats['active_connections']}"
        )
        self.ips_label.setText(f"Unique IPs: {stats['unique_ips']}")

    def log_message(self, message: str, msg_type: str = "info"):
        """Add message to log with type-based formatting"""
        if self.shutting_down or not hasattr(self, "log_text"):
            return

        if hasattr(self, "log_paused") and self.log_paused:
            return

        timestamp = datetime.now().strftime("%H:%M:%S")

        # Color coding based on message type
        if msg_type == "error":
            color = "#ff4444"
            prefix = "[ERROR]"
        elif msg_type == "alert":
            color = "#ff8800"
            prefix = "[ALERT]"
        elif msg_type == "connection":
            color = "#44aaff"
            prefix = "[CONN]"
        else:
            color = "#888888"
            prefix = "[INFO]"

        # Create HTML formatted message
        html_msg = f'<span style="color:{color}">[{timestamp}] {prefix}</span> {message}'

        try:
            self.log_text.append(html_msg)

            # Auto-scroll if enabled
            if self.log_autoscroll.isChecked():
                scrollbar = self.log_text.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())

            # Limit log size
            if self.log_text.document().blockCount() > 1000:
                cursor = self.log_text.textCursor()
                cursor.movePosition(cursor.Start)
                cursor.select(cursor.LineUnderCursor)
                cursor.removeSelectedText()
                cursor.deleteChar()  # Remove the newline
        except Exception:
            pass  # Ignore errors if widget is being destroyed

    def update_connection_details(self, conn_data: dict):
        """Update the connection details tab"""
        if self.shutting_down or not hasattr(self, "details_text"):
            return

        details = f"""
        <h3>Connection Details</h3>
        <table>
            <tr><td><b>Time:</b></td><td>{conn_data['time']}</td></tr>
            <tr><td><b>Process:</b></td><td>{conn_data['process']} (PID: {conn_data['pid']})</td></tr>
            <tr><td><b>Local Address:</b></td><td>{conn_data['local_ip']}:{conn_data['local_port']}</td></tr>
            <tr><td><b>Remote Address:</b></td><td>{conn_data['remote_ip']}:{conn_data['remote_port']}</td></tr>
            <tr><td><b>Hostname:</b></td><td>{conn_data['hostname']}</td></tr>
            <tr><td><b>Status:</b></td><td>{conn_data['status']}</td></tr>
            <tr><td><b>Category:</b></td><td>{conn_data['category']}</td></tr>
            <tr><td><b>Command Line:</b></td><td>{conn_data.get('cmdline', 'N/A')}</td></tr>
            <tr><td><b>Executable Path:</b></td><td>{conn_data.get('exe_path', 'Unknown')}</td></tr>
        </table>
        """
        try:
            self.details_text.setHtml(details)
        except Exception:
            pass

    def update_statistics(self, conn_data: dict):
        """Update statistics with new connection data"""
        self.statistics["total_connections"] += 1
        self.statistics["active_connections"] += 1

        self.statistics["unique_processes"].add(conn_data["process"])
        self.statistics["unique_ips"].add(conn_data["remote_ip"])

        if "LAN" in conn_data["category"]:
            self.statistics["lan_connections"] += 1
            self.statistics["connections_by_type"]["LAN"] += 1
        elif "Microsoft" in conn_data["category"]:
            self.statistics["microsoft_connections"] += 1
            self.statistics["connections_by_type"]["Microsoft"] += 1
        else:
            self.statistics["external_connections"] += 1
            self.statistics["connections_by_type"]["External"] += 1

        if conn_data.get("new_ip", False):
            self.statistics["new_ip_alerts"] += 1

        self.statistics["connections_by_process"][conn_data["process"]] += 1
        self.statistics["connections_by_ip"][conn_data["remote_ip"]] += 1

        hour = datetime.now().hour
        self.statistics["connections_by_hour"][hour] += 1

        key = f"{conn_data['process']}_{conn_data['remote_ip']}_{conn_data['remote_port']}"
        self.active_connection_times[key] = datetime.now()

        if (
            self.statistics["active_connections"]
            > self.statistics["peak_connections"]
        ):
            self.statistics["peak_connections"] = self.statistics[
                "active_connections"
            ]

    def update_statistics_display(self):
        """Update the statistics display"""
        try:
            if self.shutting_down or not hasattr(self, "stats_widget"):
                return

            # Calculate session duration
            session_duration = datetime.now() - self.statistics["start_time"]
            total_seconds = int(session_duration.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            # Calculate connections per minute
            total_minutes = total_seconds / 60
            if total_minutes > 0:
                connections_per_minute = (
                    self.statistics["total_connections"] / total_minutes
                )
            else:
                connections_per_minute = 0

            # Update summary labels
            self.stats_widget.labels["session_duration"].setText(
                f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            )
            self.stats_widget.labels["total_connections"].setText(
                str(self.statistics["total_connections"])
            )
            self.stats_widget.labels["active_connections"].setText(
                str(self.statistics["active_connections"])
            )
            self.stats_widget.labels["peak_connections"].setText(
                str(self.statistics["peak_connections"])
            )
            self.stats_widget.labels["connections_per_min"].setText(
                f"{connections_per_minute:.2f}"
            )
            self.stats_widget.labels["unique_processes"].setText(
                str(len(self.statistics["unique_processes"]))
            )
            self.stats_widget.labels["unique_ips"].setText(
                str(len(self.statistics["unique_ips"]))
            )
            self.stats_widget.labels["new_ip_alerts"].setText(
                str(self.statistics["new_ip_alerts"])
            )
            self.stats_widget.labels["lan_connections"].setText(
                str(self.statistics["lan_connections"])
            )
            self.stats_widget.labels["microsoft_connections"].setText(
                str(self.statistics["microsoft_connections"])
            )
            self.stats_widget.labels["external_connections"].setText(
                str(self.statistics["external_connections"])
            )

            # Update top processes with auto-scrolling
            top_procs = self.statistics["connections_by_process"].most_common(
                10
            )
            procs_text = "\n".join(
                [f"{proc}: {count}" for proc, count in top_procs]
            )
            try:
                # Store current scroll position
                scroll_pos = (
                    self.stats_widget.top_processes.verticalScrollBar().value()
                )
                self.stats_widget.top_processes.setPlainText(
                    procs_text or "No data"
                )
                # Restore scroll position if not at bottom
                if (
                    scroll_pos
                    < self.stats_widget.top_processes.verticalScrollBar().maximum()
                ):
                    self.stats_widget.top_processes.verticalScrollBar().setValue(
                        scroll_pos
                    )
            except Exception:
                pass

            # Update top destinations with auto-scrolling
            top_ips = self.statistics["connections_by_ip"].most_common(10)
            ips_text = "\n".join([f"{ip}: {count}" for ip, count in top_ips])
            try:
                # Store current scroll position
                scroll_pos = (
                    self.stats_widget.top_destinations.verticalScrollBar().value()
                )
                self.stats_widget.top_destinations.setPlainText(
                    ips_text or "No data"
                )
                # Restore scroll position if not at bottom
                if (
                    scroll_pos
                    < self.stats_widget.top_destinations.verticalScrollBar().maximum()
                ):
                    self.stats_widget.top_destinations.verticalScrollBar().setValue(
                        scroll_pos
                    )
            except Exception:
                pass

            # Update chart with hourly distribution
            hourly_data = "\n".join(
                [
                    f"{hour:02d}:00 - {count}"
                    for hour, count in sorted(
                        self.statistics["connections_by_hour"].items()
                    )
                ]
            )
            try:
                self.stats_widget.chart_label.setText(
                    f"Hourly Distribution:\n{hourly_data}"
                )
            except Exception:
                pass

        except Exception as e:
            # Silently ignore errors during shutdown
            if not self.shutting_down:
                try:
                    self.log_message(
                        f"Error updating statistics: {e}", "error"
                    )
                except Exception:
                    pass

    def format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable string"""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} TB"

    def apply_filter(self):
        """Apply filter to connection table"""
        filter_text = self.filter_input.text().lower()
        filter_type = self.filter_combo.currentText()

        for row in range(self.connection_table.rowCount()):
            should_show = True

            # Apply text filter
            if filter_text:
                row_text = ""
                for col in range(self.connection_table.columnCount()):
                    item = self.connection_table.item(row, col)
                    if item:
                        row_text += item.text().lower() + " "
                should_show = filter_text in row_text

            # Apply type filter
            if should_show and filter_type != "All":
                category_item = self.connection_table.item(row, 6)
                if category_item:
                    category = category_item.text()
                    if filter_type == "New IPs":
                        should_show = "NEW" in category
                    elif filter_type == "Microsoft":
                        should_show = "Microsoft" in category
                    elif filter_type == "External":
                        should_show = (
                            "External" in category and "NEW" not in category
                        )
                    elif filter_type == "LAN":
                        should_show = "LAN" in category

            self.connection_table.setRowHidden(row, not should_show)

    def clear_filter(self):
        """Clear all filters"""
        self.filter_input.clear()
        self.filter_combo.setCurrentIndex(0)
        for row in range(self.connection_table.rowCount()):
            self.connection_table.setRowHidden(row, False)

    def show_context_menu(self, position):
        """Show context menu for connection table"""
        menu = QMenu()

        copy_action = QAction("Copy Selected", self)
        copy_action.triggered.connect(self.copy_selected)
        menu.addAction(copy_action)

        export_selected_action = QAction("Export Selected", self)
        export_selected_action.triggered.connect(self.export_selected)
        menu.addAction(export_selected_action)

        menu.addSeparator()

        whois_action = QAction("WHOIS Lookup", self)
        whois_action.triggered.connect(self.whois_lookup)
        menu.addAction(whois_action)

        ping_action = QAction("Ping Address", self)
        ping_action.triggered.connect(self.ping_address)
        menu.addAction(ping_action)

        menu.exec_(self.connection_table.viewport().mapToGlobal(position))

    def copy_selected(self):
        """Copy selected rows to clipboard"""
        selected = self.connection_table.selectedItems()
        if not selected:
            return

        # Get unique rows
        rows = sorted(set(item.row() for item in selected))

        # Build tab-separated text
        text_lines = []
        for row in rows:
            row_items = []
            for col in range(self.connection_table.columnCount()):
                item = self.connection_table.item(row, col)
                row_items.append(item.text() if item else "")
            text_lines.append("\t".join(row_items))

        QApplication.clipboard().setText("\n".join(text_lines))
        self.log_message(f"Copied {len(rows)} rows to clipboard", "info")

    def export_selected(self):
        """Export selected connections to file"""
        selected = self.connection_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Export", "No connections selected")
            return

        rows = sorted(set(item.row() for item in selected))

        # Default to exports directory
        default_dir = str(AppPaths.get_exports_dir())
        default_name = (
            f"connections_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Selected Connections",
            os.path.join(default_dir, default_name),
            "CSV Files (*.csv);;JSON Files (*.json);;Text Files (*.txt)",
        )

        if filename:
            try:
                connections = []
                for row in rows:
                    conn_data = self.connection_table.connection_data.get(
                        row, {}
                    )
                    connections.append(conn_data)

                if filename.endswith(".json"):
                    with open(filename, "w", encoding="utf-8") as f:
                        json.dump(connections, f, indent=2, default=str)
                else:  # CSV or TXT
                    with open(
                        filename, "w", newline="", encoding="utf-8"
                    ) as f:
                        writer = csv.writer(f)
                        # Write header
                        writer.writerow(
                            [
                                "Time",
                                "Process",
                                "Remote IP",
                                "Remote Port",
                                "Hostname",
                                "Status",
                                "Category",
                                "PID",
                                "Local IP",
                                "Local Port",
                                "Command Line",
                                "Executable Path",
                            ]
                        )
                        # Write data
                        for conn in connections:
                            writer.writerow(
                                [
                                    conn.get("time", ""),
                                    conn.get("process", ""),
                                    conn.get("remote_ip", ""),
                                    conn.get("remote_port", ""),
                                    conn.get("hostname", ""),
                                    conn.get("status", ""),
                                    conn.get("category", ""),
                                    conn.get("pid", ""),
                                    conn.get("local_ip", ""),
                                    conn.get("local_port", ""),
                                    conn.get("cmdline", ""),
                                    conn.get("exe_path", ""),
                                ]
                            )

                self.log_message(
                    f"Exported {len(connections)} connections to {filename}",
                    "info",
                )
                QMessageBox.information(
                    self,
                    "Export Complete",
                    f"Successfully exported {len(connections)} connections to:\n{filename}",
                )

            except Exception as e:
                QMessageBox.critical(
                    self, "Export Error", f"Failed to export: {str(e)}"
                )
                self.log_message(f"Export error: {e}", "error")

    def whois_lookup(self):
        """Perform WHOIS lookup for selected IP"""
        selected = self.connection_table.selectedItems()
        if not selected:
            return

        # Get first selected IP
        for item in selected:
            if (
                self.connection_table.horizontalHeaderItem(
                    item.column()
                ).text()
                == "Remote IP"
            ):
                ip = item.text()
                try:
                    import webbrowser

                    webbrowser.open(f"https://whois.domaintools.com/{ip}")
                    self.log_message(f"Opening WHOIS lookup for {ip}", "info")
                except Exception as e:
                    self.log_message(f"Failed to open WHOIS: {e}", "error")
                break

    def ping_address(self):
        """Ping selected address"""
        selected = self.connection_table.selectedItems()
        if not selected:
            return

        # Get first selected IP
        for item in selected:
            if (
                self.connection_table.horizontalHeaderItem(
                    item.column()
                ).text()
                == "Remote IP"
            ):
                ip = item.text()
                try:
                    if platform.system() == "Windows":
                        subprocess.Popen(
                            f"cmd /c start cmd /k ping {ip}", shell=True
                        )
                    else:
                        subprocess.Popen(f"xterm -e ping {ip}", shell=True)
                    self.log_message(f"Pinging {ip}", "info")
                except Exception as e:
                    self.log_message(f"Failed to ping: {e}", "error")
                break

    def export_data(self, format: str = None):
        """Export data to file"""
        if not format:
            format, ok = QInputDialog.getItem(
                self,
                "Export Format",
                "Choose export format:",
                ["CSV", "JSON", "HTML", "Text"],
                0,
                False,
            )
            if not ok:
                return

        # Default to exports directory
        default_dir = str(AppPaths.get_exports_dir())
        default_name = f"network_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format.lower()}"

        filename, _ = QFileDialog.getSaveFileName(
            self,
            f"Export Data as {format}",
            os.path.join(default_dir, default_name),
            f"{format} Files (*.{format.lower()})",
        )

        if filename:
            try:
                self.progress_bar.setVisible(True)
                self.progress_bar.setRange(0, 0)  # Indeterminate progress

                # Collect all connection data
                connections = []
                for row in range(self.connection_table.rowCount()):
                    conn_data = self.connection_table.connection_data.get(
                        row, {}
                    )
                    if conn_data:
                        connections.append(conn_data)

                if format.upper() == "JSON":
                    with open(filename, "w", encoding="utf-8") as f:
                        json.dump(
                            {
                                "export_time": datetime.now().isoformat(),
                                "statistics": self.statistics,
                                "connections": connections,
                            },
                            f,
                            indent=2,
                            default=str,
                        )

                elif format.upper() == "CSV":
                    with open(
                        filename, "w", newline="", encoding="utf-8"
                    ) as f:
                        writer = csv.writer(f)
                        writer.writerow(
                            [
                                "Time",
                                "Process",
                                "Remote IP",
                                "Remote Port",
                                "Hostname",
                                "Status",
                                "Category",
                                "PID",
                                "Local IP",
                                "Local Port",
                                "Command Line",
                                "Executable Path",
                                "New IP",
                                "Process Start Time",
                            ]
                        )
                        for conn in connections:
                            writer.writerow(
                                [
                                    conn.get("time", ""),
                                    conn.get("process", ""),
                                    conn.get("remote_ip", ""),
                                    conn.get("remote_port", ""),
                                    conn.get("hostname", ""),
                                    conn.get("status", ""),
                                    conn.get("category", ""),
                                    conn.get("pid", ""),
                                    conn.get("local_ip", ""),
                                    conn.get("local_port", ""),
                                    conn.get("cmdline", ""),
                                    conn.get("exe_path", ""),
                                    str(conn.get("new_ip", False)),
                                    conn.get("create_time", ""),
                                ]
                            )

                elif format.upper() == "HTML":
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(self.generate_html_export(connections))

                else:  # Text format
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(self.generate_text_export(connections))

                self.log_message(f"Exported data to {filename}", "info")
                QMessageBox.information(
                    self,
                    "Export Complete",
                    f"Data exported successfully to:\n{filename}",
                )

            except Exception as e:
                QMessageBox.critical(
                    self, "Export Error", f"Failed to export: {str(e)}"
                )
                self.log_message(f"Export error: {e}", "error")
            finally:
                self.progress_bar.setVisible(False)

    def generate_html_export(self, connections: list) -> str:
        """Generate HTML export"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Monitor Export - {datetime.now()}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .new-ip {{ background-color: #ffcccc; }}
                .microsoft {{ background-color: #cce5ff; }}
                .external {{ background-color: #fff3cd; }}
                .lan {{ background-color: #d4edda; }}
            </style>
        </head>
        <body>
            <h1>Network Monitor Export</h1>
            <p>Export Time: {datetime.now()}</p>
            <p>Total Connections: {len(connections)}</p>

            <h2>Connection List</h2>
            <table>
                <tr>
                    <th>Time</th><th>Process</th><th>Remote IP</th><th>Port</th>
                    <th>Hostname</th><th>Status</th><th>Category</th><th>PID</th>
                </tr>
        """

        for conn in connections:
            row_class = ""
            if conn.get("new_ip", False):
                row_class = "new-ip"
            elif "Microsoft" in conn.get("category", ""):
                row_class = "microsoft"
            elif "External" in conn.get("category", ""):
                row_class = "external"
            elif "LAN" in conn.get("category", ""):
                row_class = "lan"

            html += f"""
                <tr class="{row_class}">
                    <td>{conn.get('time', '')}</td>
                    <td>{conn.get('process', '')}</td>
                    <td>{conn.get('remote_ip', '')}</td>
                    <td>{conn.get('remote_port', '')}</td>
                    <td>{conn.get('hostname', '')}</td>
                    <td>{conn.get('status', '')}</td>
                    <td>{conn.get('category', '')}</td>
                    <td>{conn.get('pid', '')}</td>
                </tr>
            """

        html += """
            </table>
        </body>
        </html>
        """
        return html

    def generate_text_export(self, connections: list) -> str:
        """Generate text export"""
        text = f"""
        Network Monitor Export
        ======================
        Export Time: {datetime.now()}
        Total Connections: {len(connections)}

        Connection List:
        {'-' * 120}
        """

        for conn in connections:
            text += f"""
        Time: {conn.get('time', '')}
        Process: {conn.get('process', '')} (PID: {conn.get('pid', '')})
        Remote: {conn.get('remote_ip', '')}:{conn.get('remote_port', '')}
        Hostname: {conn.get('hostname', '')}
        Status: {conn.get('status', '')} | Category: {conn.get('category', '')}
        Local: {conn.get('local_ip', '')}:{conn.get('local_port', '')}
        Command Line: {conn.get('cmdline', '')}
        Executable: {conn.get('exe_path', '')}
        {'-' * 80}
        """

        return text

    def clear_log(self):
        """Clear the log display"""
        self.log_text.clear()

    def clear_all(self):
        """Clear all data"""
        reply = QMessageBox.question(
            self,
            "Clear All Data",
            "Are you sure you want to clear all connection data and logs?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.connection_table.setRowCount(0)
            self.connection_table.connection_data.clear()
            self.log_text.clear()
            self.details_text.clear()

            # Reset statistics
            self.init_statistics()

            self.log_message("All data cleared", "info")

    def toggle_log_updates(self, paused: bool):
        """Toggle log updates"""
        self.log_paused = paused
        if paused:
            self.log_pause_btn.setText("Resume Updates")
        else:
            self.log_pause_btn.setText("Pause Updates")

    def toggle_auto_scroll(self, enabled: bool):
        """Toggle auto-scroll"""
        self.log_autoscroll.setChecked(enabled)

    def flush_dns(self):
        """Flush DNS cache"""
        try:
            if platform.system() == "Windows":
                subprocess.run(
                    ["ipconfig", "/flushdns"], capture_output=True, shell=True
                )
                self.log_message("DNS cache flushed", "info")
                QMessageBox.information(
                    self, "DNS Flush", "DNS cache has been flushed."
                )
            else:
                QMessageBox.information(
                    self,
                    "Not Supported",
                    "DNS flush is only supported on Windows in this version.",
                )
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to flush DNS: {str(e)}"
            )

    def show_firewall_rules(self):
        """Show generated firewall rules"""
        try:
            rules_file = AppPaths.get_firewall_suggestions_file()
            if rules_file.exists():
                with open(rules_file, "r", encoding="utf-8") as f:
                    rules = f.read()

                dialog = QDialog(self)
                dialog.setWindowTitle("Firewall Rules")
                dialog.setMinimumSize(600, 400)

                layout = QVBoxLayout()
                text_edit = QTextEdit()
                text_edit.setPlainText(rules)
                text_edit.setReadOnly(True)
                text_edit.setFont(QFont("Consolas", 9))
                layout.addWidget(text_edit)

                buttons = QDialogButtonBox(QDialogButtonBox.Ok)
                buttons.accepted.connect(dialog.accept)
                layout.addWidget(buttons)

                dialog.setLayout(layout)
                dialog.exec()
            else:
                QMessageBox.information(
                    self,
                    "No Rules",
                    "No firewall rules have been generated yet.",
                )
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Failed to read firewall rules: {str(e)}"
            )

    def show_settings(self):
        """Show settings dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Settings")
        dialog.setMinimumWidth(400)

        layout = QFormLayout()

        # Max table rows
        max_rows_spin = QSpinBox()
        max_rows_spin.setRange(100, 100000)
        max_rows_spin.setValue(
            self.settings.value("max_table_rows", 10000, type=int)
        )
        layout.addRow("Maximum Table Rows:", max_rows_spin)

        # Auto-export interval
        export_interval_spin = QSpinBox()
        export_interval_spin.setRange(1, 1440)
        export_interval_spin.setValue(
            self.settings.value("export_interval", 60, type=int)
        )
        export_interval_spin.setSuffix(" minutes")
        layout.addRow("Auto-export Interval:", export_interval_spin)

        # Start minimized
        start_minimized_check = QCheckBox()
        start_minimized_check.setChecked(
            self.settings.value("start_minimized", False, type=bool)
        )
        layout.addRow("Start Minimized:", start_minimized_check)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)

        dialog.setLayout(layout)

        if dialog.exec():
            self.settings.setValue("max_table_rows", max_rows_spin.value())
            self.settings.setValue(
                "export_interval", export_interval_spin.value()
            )
            self.settings.setValue(
                "start_minimized", start_minimized_check.isChecked()
            )

            # Update table max rows
            self.connection_table.max_rows = max_rows_spin.value()

            # Update auto-export timer
            if hasattr(self, "export_timer"):
                self.export_timer.stop()

            if self.auto_export_check.isChecked():
                export_interval = export_interval_spin.value() * 60000
                self.export_timer = QTimer()
                self.export_timer.timeout.connect(self.auto_export)
                self.export_timer.start(export_interval)

    def show_help(self):
        """Show help dialog"""
        help_text = f"""
        <h2>Network Monitor Help</h2>

        <h3>Data Storage:</h3>
        <p>All application data is stored in:<br>
        <code>{AppPaths.get_app_data_dir()}</code></p>

        <h3>Basic Usage:</h3>
        <ul>
            <li>Click <b>Start Monitoring</b> to begin capturing network connections</li>
            <li>Use the filter box to search for specific processes, IPs, or hostnames</li>
            <li>Right-click on connections for additional options (copy, export, ping, whois)</li>
            <li>Check the Statistics tab for real-time connection analysis</li>
        </ul>

        <h3>Alert Types:</h3>
        <ul>
            <li><span style="color:#ff4444">Red</span>: New external IP detected</li>
            <li><span style="color:#44aaff">Blue</span>: Microsoft services</li>
            <li><span style="color:#4CAF50">Green</span>: Local network (LAN) connections</li>
            <li><span style="color:#ff9800">Yellow</span>: Other external connections</li>
        </ul>

        <h3>Firewall Rules:</h3>
        <p>The application generates firewall rules for new suspicious connections.
        These are saved in batch files that can be run as Administrator to block connections.</p>

        <h3>Export Options:</h3>
        <p>You can export data in multiple formats (CSV, JSON, HTML, Text).
        Use the Export menu or toolbar button to save your data.</p>

        <h3>Tips:</h3>
        <ul>
            <li>Use the system tray icon to minimize to background</li>
            <li>Enable auto-export for regular backups of your data</li>
            <li>Check the Event Log tab for detailed connection history</li>
            <li>Use the 📁 button to open the data directory</li>
        </ul>
        """

        dialog = QDialog(self)
        dialog.setWindowTitle("Help")
        dialog.setMinimumSize(500, 600)

        layout = QVBoxLayout()
        text_edit = QTextEdit()
        text_edit.setHtml(help_text)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dialog.accept)
        layout.addWidget(buttons)

        dialog.setLayout(layout)
        dialog.exec()

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About Network Monitor",
            f"""
            <h2>Network Monitor {__version__}</h2>
            <p>A real-time network connection monitoring tool.</p>

            <p><b>Data Directory:</b><br>
            {AppPaths.get_app_data_dir()}</p>

            <p><b>Features:</b></p>
            <ul>
                <li>Real-time network connection monitoring</li>
                <li>Process identification and categorization</li>
                <li>New connection alerts and notifications</li>
                <li>Firewall rule generation</li>
                <li>Statistics and data analysis</li>
                <li>Multiple export formats</li>
                <li>System tray integration</li>
            </ul>

            <p><b>Platform:</b> Windows (with psutil support)</p>
            <p><b>License:</b> MIT License</p>
            <p><b>GitHub:</b> github.com/bouness/network-monitor</p>
            """,
        )

    def show_documentation(self):
        """Open documentation in browser"""
        try:
            QDesktopServices.openUrl(
                "https://github.com/bouness/network-monitor/wiki"
            )
        except Exception:
            QMessageBox.information(
                self,
                "Documentation",
                "Online documentation is available at:\nhttps://github.com/bouness/network-monitor/wiki",
            )

    def auto_export(self):
        """Automatically export data"""
        try:
            filename = AppPaths.get_auto_export_file()

            connections = []
            for row in range(self.connection_table.rowCount()):
                conn_data = self.connection_table.connection_data.get(row, {})
                if conn_data:
                    connections.append(conn_data)

            if connections:
                data = {
                    "export_time": datetime.now().isoformat(),
                    "statistics": self.statistics,
                    "connections": connections,
                }

                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str)

                self.log_message(f"Auto-exported to {filename}", "info")
        except Exception as e:
            self.log_message(f"Auto-export failed: {e}", "error")

    def autosave(self):
        """Auto-save application state"""
        try:
            self.save_settings()
        except Exception as e:
            print(f"Auto-save error: {e}")

    def load_settings(self):
        """Load application settings"""
        for key, default in DEFAULT_CONFIG.items():
            if not self.settings.contains(key):
                self.settings.setValue(key, default)

    def apply_settings(self):
        """Apply saved settings to UI"""
        self.interval_spin.setValue(
            self.settings.value("refresh_interval", 1, type=int)
        )
        self.alerts_check.setChecked(
            self.settings.value("enable_alerts", True, type=bool)
        )
        self.sound_check.setChecked(
            self.settings.value("enable_sound", True, type=bool)
        )
        self.log_check.setChecked(
            self.settings.value("log_to_file", True, type=bool)
        )
        self.notify_new_ip.setChecked(
            self.settings.value("notify_new_ip", True, type=bool)
        )
        self.auto_export_check.setChecked(
            self.settings.value("auto_export", False, type=bool)
        )

    def save_settings(self):
        """Save application settings"""
        self.settings.setValue("refresh_interval", self.interval_spin.value())
        self.settings.setValue("enable_alerts", self.alerts_check.isChecked())
        self.settings.setValue("enable_sound", self.sound_check.isChecked())
        self.settings.setValue("log_to_file", self.log_check.isChecked())
        self.settings.setValue("notify_new_ip", self.notify_new_ip.isChecked())
        self.settings.setValue(
            "auto_export", self.auto_export_check.isChecked()
        )

        # Save window geometry
        if not self.shutting_down:
            self.settings.setValue("geometry", self.saveGeometry())
            self.settings.setValue("window_state", self.saveState())

    def showEvent(self, event):
        """Handle window show event"""
        super().showEvent(event)

        # Restore window geometry
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)

        state = self.settings.value("window_state")
        if state:
            self.restoreState(state)

    def resizeEvent(self, event):
        """Handle window resize event"""
        super().resizeEvent(event)
        # Update layouts when window is resized
        if hasattr(self, "stats_widget"):
            self.stats_widget.updateGeometry()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Network Monitor")
    app.setOrganizationName("NetworkMonitor")
    app.setApplicationDisplayName("Network Monitor")

    # Set application style - use system default
    app.setStyle("Fusion")  # Fusion works well on all platforms
    app_icon = QIcon(resource_path("assets/icon.png"))
    app.setWindowIcon(app_icon)

    # Ensure directories exist
    AppPaths.ensure_directories()

    window = NetworkMonitorGUI()

    # Start minimized if configured
    if window.settings.value("start_minimized", False, type=bool):
        window.showMinimized()
    else:
        window.show()

    # Set up proper application termination
    def cleanup():
        window.shutting_down = True
        if hasattr(window, "monitor_thread") and window.monitor_thread:
            window.monitor_thread.stop()

    app.aboutToQuit.connect(cleanup)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
