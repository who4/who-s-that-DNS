# Who's This DNS! 🕵️‍♂️🌐

**Who's This DNS!** is a modern, dark-mode desktop utility built with Python and CustomTkinter to scan, verify, and verify public DNS servers.

It doesn't just check if a server is online—it verifies if it actually resolves DNS queries.

![Screenshot Placeholder](https://via.placeholder.com/800x400?text=Who%27s+This+DNS+Screenshot)

## 🚀 Features

-   **Dual-Check Engine**:
    -   **Ping (ICMP)**: Checks if the host is reachable.
    -   **DNS (UDP 53)**: Verifies if the host actually resolves names (queries `google.com`).
-   **Smart Import**:
    -   Supports single IPs (e.g., `1.1.1.1`)
    -   Supports **CIDR Blocks** (e.g., `104.23.155.0/24` expands to all 256 IPs).
-   **Auto-Fetch**: Download specifically curated public DNS lists directly from the web.
-   **Live Statistics**: Real-time counter of alive vs. dead servers.
-   **JSON Export**: Save your findings for later use.

## 🛠️ Installation

1.  **Clone the repo** (or download files):
    ```bash
    git clone https://github.com/yourusername/whos-this-dns.git
    cd whos-this-dns
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 🖥️ Usage

1.  Run the application:
    ```bash
    python main.py
    ```
2.  **Choose Source**:
    -   **Fetch from Web**: Automatically downloads a fresh list of public DNS servers.
    -   **Load from .txt**: Pick a text file containing IPs or CIDR ranges.
3.  Click **START SCAN**.
4.  Watch the table populate with results.
    -   🟢 **Green**: Working perfectly.
    -   🔴 **Red**: Offline / Timeout.

## 📦 Requirements

-   Python 3.8+
-   `customtkinter`
-   `dnspython`
-   `requests`

## 📄 License

MIT License. Free to use and modify!
