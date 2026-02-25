# 🔒 Secure Bluetooth File Transfer
<img width="517" height="644" alt="image" src="https://github.com/user-attachments/assets/5beae7be-0aee-4ad0-bef9-b0885a8d964d" />

A secure, cross-platform desktop application for transferring files between devices over Bluetooth. Built with Python and PyQt5, this tool ensures your data remains private during transit by utilizing AES-GCM end-to-end encryption. 

To assist with development and environments without Bluetooth hardware, the app also features a built-in **Logic Test Mode** that simulates transfers using internal thread queues.

## ✨ Features
* **End-to-End Encryption:** All files are encrypted before transmission using `AES-GCM`, with keys securely derived via PBKDF2HMAC (SHA256).
* **Bi-Directional Communication:** The application simultaneously runs server and client threads, allowing you to seamlessly send and receive files from the same interface.
* **Hardware-Free Testing:** A dedicated "Logic Test" mode bypasses the Bluetooth stack to test the encryption, chunking, and GUI logic entirely in memory.
* **Modern GUI:** A clean, responsive user interface built with PyQt5, featuring real-time progress bars, connection status updates, and a live event log.

---

## 🚀 Installation & Prerequisites

To run this application, you will need Python 3.x installed along with a few dependencies. 

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mykola-volynets/encrypted-bluetooth-communicator.git
   cd encrypted-bluetooth-communicator

   ```

2. **Install the required dependencies:**
Using the provided `requirements.txt` file, run the following command to install all necessary packages:
   ```bash
   pip install -r requirements.txt

   ```


*Note on PyBluez: Depending on your operating system (especially Windows), installing `PyBluez` might require the C++ Build Tools. If the installation fails or you cannot install PyBluez, the application will still launch and gracefully fallback to allow you to use the "Logic Test" mode!*

---

## 🛠️ Configuration & Security Notice

**Important:** Out of the box, the application uses a hardcoded pre-shared secret and salt for demonstration purposes.

Before using this for actual secure transfers, open `src/main.py` and modify the following lines (around line 34) on **both** sending and receiving machines to match:

```python
PRE_SHARED_SECRET = b"YourSuperSecretPasswordHere"
SALT = b'YourUniqueSaltHere'

```

---

## 💻 How to Use

### Bluetooth Mode (Real Devices)

1. Ensure Bluetooth is enabled on both devices and that they are paired.
2. Launch the application on both devices: `python src/main.py`.
3. On the **Sender** device, click **Scan Devices** to discover the Receiver.
4. Select the Receiver from the Device List.
5. Click **Select File**, choose your file, and click **Send File**.

### Logic Test Mode (Local Testing)

1. Launch the application.
2. Check the **"Logic Test (No Bluetooth)"** box in the Connection panel.
3. Click **Select File**, choose a file, and click **Send File**.
4. The application will encrypt the file, pass it through an internal queue system to simulate network latency, decrypt it, and save it locally (prefixed with `logic_test_`).
