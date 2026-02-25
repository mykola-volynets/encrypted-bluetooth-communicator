import sys
import os
import time
import threading
import json
import queue
import traceback
import socket

# Attempt to import bluetooth, handle potential import error gracefully
try:
    import bluetooth
except ImportError:
    print("WARNING: PyBluez library not found. Bluetooth functionality will be unavailable.", file=sys.stderr)
    print("You can still use the 'Logic Test (No Bluetooth)' mode.", file=sys.stderr)
    bluetooth = None

from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import pyqtSignal, QObject, QThread, Qt
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QCheckBox

# --- Cryptography Imports ---
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend

    cryptography_available = True
except ImportError:
    print("ERROR: cryptography library not found. Please install it (`pip install cryptography`)", file=sys.stderr)
    cryptography_available = False

    # Define dummy classes/functions if cryptography is missing to avoid NameErrors later
    # This allows the UI to potentially still load, but encryption/decryption will fail.

    class AESGCM:
        def __init__(self, key): pass

        def encrypt(self, nonce, data, associated_data): raise RuntimeError("cryptography library missing")

        def decrypt(self, nonce, data, associated_data): raise RuntimeError("cryptography library missing")
    # No need for KDF/Hashes dummies if AESGCM fails first

# --- Configuration ---
PRE_SHARED_SECRET = b"YourSecretPasswordHere"
SALT = b'YourSaltHere'  # Keep secret & unique
AES_KEY = None
if cryptography_available:
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100000,  # Adjust iterations based on security needs/performance
            backend=default_backend()
        )
        AES_KEY = kdf.derive(PRE_SHARED_SECRET)
    except Exception as e:
        print(f"ERROR: Failed to derive AES key: {e}", file=sys.stderr)
        cryptography_available = False  # Disable crypto if key derivation fails

# Unique UUID for the Bluetooth service (only used if bluetooth is available)
SERVICE_UUID = "4b2d9a1e-8f3b-4c72-a1e5-6d9b8a2f4e0c"
SERVICE_NAME = "SecureBluetoothFileTransfer"
BUFFER_SIZE = 40960  # Data chunk size


# --- Worker Signals ---
class WorkerSignals(QObject):
    device_discovered = pyqtSignal(str, str)
    scan_finished = pyqtSignal()
    connection_status = pyqtSignal(str)
    log_message = pyqtSignal(str)
    progress_update = pyqtSignal(int)
    transfer_complete = pyqtSignal(bool, str)
    enable_send_button = pyqtSignal(bool)
    clear_device_list = pyqtSignal()
    set_file_path = pyqtSignal(str)


# --- ScannerThread (Only used in Bluetooth mode) ---
class ScannerThread(QThread):
    def __init__(self, signals):
        super().__init__()
        self.signals = signals

    def run(self):
        if not bluetooth:
            self.signals.log_message.emit("Bluetooth library not available. Scan skipped.")
            self.signals.scan_finished.emit()
            return

        self.signals.log_message.emit("Starting Bluetooth device scan...")
        self.signals.clear_device_list.emit()
        try:
            nearby_devices = bluetooth.discover_devices(duration=5, lookup_names=True,
                                                        flush_cache=True, lookup_class=False)
            if not nearby_devices:
                self.signals.log_message.emit("No external Bluetooth devices found.")
            else:
                self.signals.log_message.emit(f"Found {len(nearby_devices)} external device(s):")
                for addr, name in nearby_devices:
                    # Ensure name is decoded if necessary (PyBluez might return bytes)
                    if isinstance(name, bytes):
                        try:
                            name = name.decode('utf-8', errors='replace')
                        except Exception:
                            name = str(name)  # Fallback if decoding fails
                    self.signals.log_message.emit(f" - {name} ({addr})")
                    # Emit signal to add device to the UI list
                    self.signals.device_discovered.emit(name, addr)
        except bluetooth.btcommon.BluetoothError as e:
            # Handle potential Bluetooth errors during scan (e.g., adapter off)
            self.signals.log_message.emit(f"Bluetooth Error during scan: {e}. Is Bluetooth enabled?")
        except Exception as e:
            # Handle any other unexpected errors during scan
            self.signals.log_message.emit(f"Error during scan: {e}")
            self.signals.log_message.emit(traceback.format_exc())  # Log full traceback for debugging
        finally:
            # Signal that the scan process has finished
            self.signals.log_message.emit("Scan finished.")
            self.signals.scan_finished.emit()


# --- ServerThread (Handles both Bluetooth and Logic Test modes) ---
class ServerThread(QThread):
    def __init__(self, signals, client_to_server_queue, server_to_client_queue):
        super().__init__()
        self.signals = signals
        # Queues for Logic Test mode communication
        self.client_queue = client_to_server_queue
        self.server_queue = server_to_client_queue
        # Bluetooth specific attributes
        self.server_sock = None  # Server's listening socket
        self.client_sock = None  # Socket for connected client
        self._local_address = None  # Store local BT address if found
        # Mode control
        self.running = True  # Flag to control the main loop
        self.is_logic_test_mode = False  # Default to Bluetooth mode

    def set_logic_test_mode(self, is_test_mode):
        """Sets the operational mode (True for Logic Test, False for Bluetooth)."""
        # This method is called by the main GUI thread to change the mode.
        # Note: Changing this flag while the thread is running inside its loop
        # might not immediately change behavior if the thread is blocked (e.g., on accept()).
        # The run() method checks this flag at the beginning. Restarting the thread
        # is the reliable way to switch modes.
        self.is_logic_test_mode = is_test_mode
        mode_str = "Logic Test" if is_test_mode else "Bluetooth"
        # Log the mode change (signal will be processed by GUI thread)
        self.signals.log_message.emit(f"Server mode set to: {mode_str}")

    def stop(self):
        """Signals the thread to stop and cleans up resources."""
        self.signals.log_message.emit("Server stop requested.")
        self.running = False  # Signal the main loops to exit

        # --- Resource Cleanup ---
        # Unblock queue if in logic test mode and potentially waiting on client_queue.get()
        if self.is_logic_test_mode:
            try:
                # Put a sentinel value (None) to unblock the queue.get() call
                self.client_queue.put_nowait(None)
            except queue.Full:
                # If queue is full, it means the thread is likely busy or already stopping.
                pass

        # Close Bluetooth sockets if they exist and we were running in BT mode
        if not self.is_logic_test_mode:
            # Important: Close client socket first if it exists
            if self.client_sock:
                try:
                    # Attempt a graceful shutdown of the connection
                    self.client_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass  # Ignore errors if socket already closed/invalid
                try:
                    self.client_sock.close()
                    self.signals.log_message.emit("Client socket closed.")
                except Exception:
                    pass
                self.client_sock = None  # Clear reference

            # Then close the server's listening socket
            if self.server_sock:
                try:
                    # Stop advertising the service before closing the socket
                    # Note: This might fail if advertising wasn't started or already stopped.
                    if bluetooth:  # Check if bluetooth module is available
                        try:
                            bluetooth.stop_advertising(self.server_sock)
                            self.signals.log_message.emit("Stopped Bluetooth advertising.")
                        except Exception as ad_err:
                            # Log minor errors during cleanup, don't prevent stopping
                            self.signals.log_message.emit(f"Minor error stopping advertising: {ad_err}")
                            pass
                    self.server_sock.close()
                    self.signals.log_message.emit("Server socket closed.")
                except Exception as e:
                    # Log error during cleanup if needed
                    self.signals.log_message.emit(f"Minor error closing server socket: {e}")
                    pass
                self.server_sock = None  # Clear reference

        # Wait for the thread's run() method to exit (up to 2 seconds)
        # self.wait(2000) # wait() should be called from the thread that started this one (GUI thread)

    def get_local_address(self):
        """Attempts to read the local Bluetooth address."""
        if not bluetooth: return None  # Skip if library not available
        # Cache the local address to avoid repeated lookups
        if not self._local_address:
            try:
                addr_tuple = bluetooth.read_local_bdaddr()
                self._local_address = addr_tuple[0] if addr_tuple else None
            except Exception as e:
                # Log error if reading local address fails
                self.signals.log_message.emit(f"Could not read local Bluetooth address: {e}")
                self._local_address = None
        return self._local_address

    def run(self):
        """Main loop for the server thread. Chooses path based on mode."""
        # This method runs when the thread starts.
        # It checks the mode flag ONCE and enters the corresponding loop.
        if self.is_logic_test_mode:
            self.run_logic_test_server()
        elif bluetooth:  # Only run Bluetooth server if library is available
            self.run_bluetooth_server()
        else:
            # If BT library is missing and not in logic test mode
            self.signals.log_message.emit("Bluetooth library not available. Server not started.")
            self.signals.connection_status.emit("Status: Bluetooth Unavailable")

        # This code runs when the loop in run_logic_test_server or run_bluetooth_server exits
        self.signals.log_message.emit("Server thread run method finished.")
        # Final status update when thread exits (unless already stopped)
        if self.running:  # Check if stopped externally
            self.signals.connection_status.emit("Status: Server Stopped Unexpectedly")
        else:
            self.signals.connection_status.emit("Status: Server Stopped")

    def run_logic_test_server(self):
        """Server loop for Logic Test mode using queues."""
        self.signals.log_message.emit("Server running in Logic Test mode (No Bluetooth). Waiting for data...")
        self.signals.connection_status.emit("Status: Logic Test Mode / Idle")
        while self.running:  # Loop continues as long as running flag is True
            try:
                # Block and wait for the client thread to put the first piece of data (metadata)
                # Use timeout (e.g., 1 second) to periodically check self.running flag
                metadata_json_bytes = self.client_queue.get(timeout=1.0)

                if metadata_json_bytes is None:  # Check for the sentinel value used in stop()
                    self.signals.log_message.emit("Received stop signal on queue. Exiting logic test loop.")
                    break  # Exit the while loop
                if not self.running: break  # Check running flag again after blocking call

                # If data received, process the transfer
                self.signals.log_message.emit("Received data signal in Logic Test mode.")
                self.signals.connection_status.emit("Status: Processing Logic Test Transfer")
                # Handle the transfer using queues, pass initial data
                self.handle_transfer(sock=None, is_loopback=True, initial_data=metadata_json_bytes)
                # After handling, reset status (ready for next transfer in this mode)
                self.signals.connection_status.emit("Status: Logic Test Mode / Idle")

            except queue.Empty:
                # Timeout occurred on client_queue.get(). This is normal.
                # Loop again to check self.running flag and wait for data again.
                continue
            except Exception as e:
                # Handle unexpected errors during the loop
                if self.running:  # Only log if not intentionally stopping
                    self.signals.log_message.emit(f"Error in Logic Test server loop: {e}")
                    self.signals.log_message.emit(traceback.format_exc())
                    time.sleep(1)  # Avoid busy-looping on persistent errors

    def run_bluetooth_server(self):
        """Server loop for Bluetooth mode."""
        self.signals.log_message.emit("Starting Bluetooth server...")
        try:
            # Get local BT address (needed for loopback check)
            self._local_address = self.get_local_address()
            if self._local_address:
                self.signals.log_message.emit(f"Server using local address: {self._local_address}")
            else:
                self.signals.log_message.emit("Warning: Could not determine local Bluetooth address.")
                # Consider stopping if local address is crucial for operation

            # --- Setup Bluetooth Socket ---
            self.server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            # Bind to any available local adapter, using an available RFCOMM port
            self.server_sock.bind(("", bluetooth.PORT_ANY))
            # Listen for incoming connections (queue size 1)
            self.server_sock.listen(1)
            # Get the dynamically assigned port number
            port = self.server_sock.getsockname()[1]

            # --- Advertise Bluetooth Service ---
            bluetooth.advertise_service(self.server_sock, SERVICE_NAME,
                                        service_id=SERVICE_UUID,
                                        service_classes=[SERVICE_UUID, bluetooth.SERIAL_PORT_CLASS],
                                        profiles=[bluetooth.SERIAL_PORT_PROFILE])

            self.signals.log_message.emit(f"Bluetooth Server listening on RFCOMM channel {port}")
            self.signals.connection_status.emit("Status: Listening / Idle")

            # --- Main Accept Loop ---
            while self.running:
                client_info_str = "Unknown"  # For logging
                try:
                    self.signals.log_message.emit("Waiting for Bluetooth connection...")
                    # Set a timeout on accept() to allow checking self.running periodically
                    self.server_sock.settimeout(10.0)  # Timeout after 1 second
                    try:
                        # Block until a connection is received or timeout occurs
                        self.client_sock, client_info = self.server_sock.accept()
                        client_info_str = str(client_info)  # For logging
                    except bluetooth.btcommon.BluetoothError as e:
                        # If timeout occurs, str(e) often contains "timed out"
                        if "timed out" in str(e).lower():
                            # This is expected, just continue the loop to check self.running
                            continue
                        else:
                            # Re-raise other Bluetooth errors during accept
                            raise
                    finally:
                        # Always disable the timeout after accept() returns or times out
                        self.server_sock.settimeout(1.0)

                    # Check if stop() was called while blocked in accept()
                    if not self.running: break

                    # --- Handle Accepted Connection ---
                    self.signals.log_message.emit(f"Accepted Bluetooth connection from {client_info_str}")

                    # Determine if it's a loopback connection (client connected from same adapter)
                    is_loopback = False
                    if self._local_address and client_info and client_info[0] == self._local_address:
                        is_loopback = True
                        self.signals.connection_status.emit(f"Status: Connected (Loopback Test)")
                    elif client_info:
                        self.signals.connection_status.emit(f"Status: Connected to {client_info[0]}")
                    else:
                        self.signals.connection_status.emit(f"Status: Connected (Unknown Client)")

                    # Process the file transfer with the connected client socket
                    self.handle_transfer(sock=self.client_sock, is_loopback=is_loopback)
                    # After handle_transfer finishes (or fails), update status
                    self.signals.connection_status.emit("Status: Disconnected")
                    self.signals.log_message.emit(f"Client {client_info_str} disconnected.")

                except bluetooth.btcommon.BluetoothError as e:
                    # Handle Bluetooth errors occurring in the accept loop
                    if self.running:  # Only log if not intentionally stopping
                        err_str = str(e).lower()
                        # Ignore common errors that might occur during shutdown or temporary issues
                        if "timed out" not in err_str and \
                                "socket" not in err_str and \
                                "resource temporarily unavailable" not in err_str and \
                                "connection aborted" not in err_str:
                            self.signals.log_message.emit(f"Server Bluetooth Error: {e}")
                            # Consider if the server should stop on certain persistent errors
                    if not self.running: break  # Exit loop if stop() was called
                    time.sleep(0.5)  # Short pause before retrying accept

                except Exception as e:
                    # Handle non-Bluetooth errors during the accept loop
                    if self.running:
                        self.signals.log_message.emit(f"Error accepting connection from {client_info_str}: {e}")
                        self.signals.log_message.emit(traceback.format_exc())
                    time.sleep(1)  # Avoid busy-looping on non-BT errors
                finally:
                    # --- Crucial Cleanup ---
                    # Ensure client socket is closed after handling or if an error occurred
                    # before handle_transfer completed.
                    if self.client_sock:
                        try:
                            self.client_sock.close()
                        except Exception:
                            pass
                        self.client_sock = None  # Reset client socket reference

        except bluetooth.btcommon.BluetoothError as e:
            # Handle errors during initial server setup (bind, listen, advertise)
            self.signals.log_message.emit(f"Fatal Bluetooth Server Setup Error: {e}. Is Bluetooth enabled/available?")
            self.signals.connection_status.emit("Status: Server Error (BT)")
        except Exception as e:
            # Handle other errors during server setup
            self.signals.log_message.emit(f"Server setup failed: {e}")
            self.signals.log_message.emit(traceback.format_exc())
            self.signals.connection_status.emit("Status: Server Error")
        finally:
            # Final cleanup when the server loop exits (also done in stop())
            if self.server_sock:
                try:
                    # Stop advertising if socket is valid before closing
                    if bluetooth and self.server_sock.fileno() != -1:  # Check if valid socket descriptor
                        try:
                            bluetooth.stop_advertising(self.server_sock)
                        except Exception:
                            pass  # Ignore errors stopping advertising
                    self.server_sock.close()
                except Exception:
                    pass
                self.server_sock = None
            self.signals.log_message.emit("Bluetooth server loop finished.")

    def handle_transfer(self, sock, is_loopback=False, initial_data=None):
        """Handles receiving a file via Bluetooth socket OR logic test queues."""
        # Check if cryptography is ready
        if not cryptography_available or not AES_KEY:
            self.signals.log_message.emit("Error: Cryptography not available or key missing. Cannot receive file.")
            self.signals.transfer_complete.emit(False, "Receive failed: Cryptography setup error")
            if sock: sock.close()  # Close socket if provided
            return

        current_sock = sock  # Use local variable for socket to avoid modifying self.client_sock directly here
        local_filename = None  # Initialize filename variable for cleanup
        bytes_received = 0  # Track received bytes for cleanup logic
        filesize = -1  # Initialize filesize

        try:
            # --- 1. Receive Metadata ---
            metadata_json_bytes = None
            if current_sock:  # Bluetooth mode
                # Set a reasonable timeout for receiving metadata
                current_sock.settimeout(20.0)
                metadata_json_bytes = current_sock.recv(BUFFER_SIZE)
                current_sock.settimeout(1.0)  # Disable timeout for the main transfer phase
            else:  # Logic test mode
                # Metadata is passed directly from the run_logic_test_server loop
                metadata_json_bytes = initial_data

            # Check if connection closed or stop signal received
            if not metadata_json_bytes:
                self.signals.log_message.emit("Received empty metadata or stop signal. Closing connection.")
                if current_sock: current_sock.close()
                return  # Exit transfer handling

            # Decode and parse metadata
            metadata_json = metadata_json_bytes.decode('utf-8')
            metadata = json.loads(metadata_json)
            filename = metadata['filename']
            filesize = metadata['filesize']  # Store filesize for later checks
            nonce = bytes.fromhex(metadata['nonce'])  # Convert hex nonce back to bytes
            self.signals.log_message.emit(f"Receiving file: {filename} ({filesize} bytes)")

            # --- Send Confirmation ---
            if current_sock:
                current_sock.send(b'OK')  # Send confirmation over Bluetooth socket
            else:
                self.server_queue.put(b'OK')  # Put confirmation onto the queue for client thread

            # Prepare AES GCM object for decryption
            aesgcm = AESGCM(AES_KEY)

            # --- Prepare Local File ---
            # Create a unique local filename to avoid overwriting
            prefix = "logic_test_" if not current_sock else ("loopback_" if is_loopback else "received_")
            # Basic sanitization of filename from metadata
            safe_basename = os.path.basename(filename).replace('\\', '_').replace('/', '_')
            base, ext = os.path.splitext(safe_basename)
            counter = 1
            # Default download location (current directory) - consider making this configurable
            download_dir = "."
            local_filename = os.path.join(download_dir, f"{prefix}{safe_basename}")
            # Append counter if file already exists
            while os.path.exists(local_filename):
                local_filename = os.path.join(download_dir, f"{prefix}{base}_{counter}{ext}")
                counter += 1
            self.signals.log_message.emit(f"Saving incoming file as: {local_filename}")

            # --- 2. Receive File Data ---
            start_time = time.time()
            self.signals.progress_update.emit(0)  # Ensure progress starts at 0

            # Open the local file for writing in binary mode
            with open(local_filename, 'wb') as f:
                while bytes_received < filesize:
                    print('fs', filesize)
                    # Calculate expected size of next chunk (data + 16-byte GCM tag)
                    remaining_data_bytes = filesize - bytes_received
                    # Ensure we don't try to read more than needed, including the tag
                    read_size_expected = remaining_data_bytes + 16
                    # Read either buffer size + tag, or remaining expected size, whichever is smaller
                    chunk_to_read = min(BUFFER_SIZE + 16, read_size_expected)
                    print(chunk_to_read)

                    # --- Receive Full Encrypted Chunk + Tag ---
                    encrypted_chunk_with_tag = b""
                    bytes_needed_for_chunk = chunk_to_read  # Calculated earlier in your loop

                    # Loop to receive the complete chunk+tag data
                    while len(encrypted_chunk_with_tag) < bytes_needed_for_chunk:
                        remaining_bytes = bytes_needed_for_chunk - len(encrypted_chunk_with_tag)
                        part = b""  # Initialize part as empty bytes

                        if current_sock:  # Bluetooth mode
                            try:
                                # Set timeout for this specific recv call
                                current_sock.settimeout(15.0)
                                part = current_sock.recv(remaining_bytes)
                                # print(f"Received {len(part)} bytes (BT), needed {remaining_bytes}") # Debug print
                                current_sock.settimeout(
                                    1.0)  # Reset timeout (or back to a default like 1.0 if needed elsewhere)
                            except bluetooth.btcommon.BluetoothError as bt_err:
                                if "timed out" in str(bt_err).lower():
                                    self.signals.log_message.emit("Timeout waiting for data chunk (BT).")
                                    raise TimeoutError("Timeout waiting for data chunk (BT).")
                                else:
                                    self.signals.log_message.emit(f"Bluetooth error receiving chunk: {bt_err}")
                                    raise ConnectionAbortedError(f"Bluetooth error receiving chunk: {bt_err}")
                            except Exception as sock_err:
                                # Handle other potential socket errors
                                self.signals.log_message.emit(f"Socket error receiving chunk: {sock_err}")
                                raise ConnectionAbortedError(f"Socket error receiving chunk: {sock_err}")

                        else:  # Logic test mode
                            try:
                                part = self.client_queue.get(timeout=15.0)
                                # print(f"Received {len(part)} bytes (Queue), needed {remaining_bytes}") # Debug print
                                if part is None:  # Check for termination signal from client
                                    raise ConnectionAbortedError(
                                        "Client signaled end prematurely (queue) during chunk receive.")
                            except queue.Empty:
                                self.signals.log_message.emit("Timeout waiting for data chunk from client queue.")
                                raise TimeoutError("Timeout waiting for data chunk from client queue.")

                        # Check if the connection was closed or queue ended unexpectedly
                        if not part:
                            self.signals.log_message.emit(
                                f"Connection closed or queue empty unexpectedly while receiving chunk. Got {len(encrypted_chunk_with_tag)} of {bytes_needed_for_chunk}.")
                            raise ConnectionAbortedError("Connection lost or queue empty unexpectedly during transfer.")

                        encrypted_chunk_with_tag += part

                    # --- Decrypt and Write Chunk ---
                    # The 'try...except Exception as decrypt_error:' block follows immediately after this new code.
                    try:
                        # (Your original decryption and writing code starts here)
                        print(f"Attempting to decrypt {len(encrypted_chunk_with_tag)} bytes...")  # Debug print
                        decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk_with_tag, None)  # No associated data
                        # ... rest of your original try block ...
                        f.write(decrypted_chunk)
                        bytes_received += len(decrypted_chunk)  # Update progress based on *decrypted* data size

                        # Update progress bar
                        if filesize > 0:
                            progress = int(100 * bytes_received / filesize)
                            self.signals.progress_update.emit(progress)
                        else:
                            # Handle zero-byte file case (progress immediately 100)
                            self.signals.progress_update.emit(100)

                    except Exception as decrypt_error:  # Catch specific decryption/authentication errors
                        # cryptography raises InvalidTag or other exceptions on failure
                        self.signals.log_message.emit(f"Decryption/Authentication failed: {decrypt_error}")
                        # Raise a specific error to be caught by the outer try/except
                        raise ValueError(f"Decryption failed: {decrypt_error}")

            # --- Transfer Complete ---
            # After the loop, verify if all expected bytes were received
            if bytes_received != filesize:
                # This case might occur if the connection drops precisely after the last chunk write
                # but before this check. Or if metadata filesize was wrong.
                raise IOError(f"File transfer incomplete. Expected {filesize} bytes, received {bytes_received}")

            end_time = time.time()
            duration = end_time - start_time
            transfer_speed = (filesize / duration / 1024) if duration > 0 else 0  # KB/s

            # Final progress update and success message
            self.signals.progress_update.emit(100)
            self.signals.log_message.emit(
                f"File '{local_filename}' received successfully in {duration:.2f}s ({transfer_speed:.2f} KB/s).")
            # Signal transfer success to the GUI
            self.signals.transfer_complete.emit(True, f"Received '{os.path.basename(local_filename)}'")

        # --- Error Handling ---
        except json.JSONDecodeError:
            self.signals.log_message.emit("Error: Invalid metadata received.")
            self.signals.transfer_complete.emit(False, "Receive failed: Invalid metadata")
        except (ConnectionAbortedError, TimeoutError, IOError, ValueError) as e:  # Catch specific, expected errors
            self.signals.log_message.emit(f"Error during receive: {e}")
            self.signals.transfer_complete.emit(False, f"Receive failed: {e}")
        except bluetooth.btcommon.BluetoothError as e:
            # Handle Bluetooth-specific errors during transfer
            err_str = str(e).lower()
            # Only log if running and error isn't a common "connection closed" type
            if self.running and "socket" not in err_str and "connection aborted" not in err_str:
                self.signals.log_message.emit(f"Bluetooth Error during receive: {e}")
                self.signals.transfer_complete.emit(False, f"Receive failed (BT): {e}")
        except Exception as e:
            # Catch any other unexpected errors
            self.signals.log_message.emit(f"Unexpected error receiving file: {e}")
            self.signals.log_message.emit(traceback.format_exc())  # Log full traceback
            self.signals.transfer_complete.emit(False, f"Receive failed: {e}")
        finally:
            # --- Final Cleanup for handle_transfer ---
            # Clean up partially received file if an error occurred *during* transfer
            # Check if filename was determined, file exists, and received bytes < expected
            if local_filename and os.path.exists(local_filename) and filesize >= 0 and (bytes_received < filesize):
                try:
                    # Ensure file handle is closed if 'with open' block exited prematurely
                    # (though 'with' should handle this, belt-and-suspenders)
                    if 'f' in locals() and not f.closed:
                        f.close()
                    # os.remove(local_filename)
                    self.signals.log_message.emit(f"Removed incomplete file: {local_filename}")
                except OSError as remove_err:
                    self.signals.log_message.emit(f"Could not remove partial file {local_filename}: {remove_err}")

            # Close socket if it was provided and might still be open
            if current_sock:
                try:
                    current_sock.close()
                except Exception:
                    pass
            # Reset progress bar in the GUI
            self.signals.progress_update.emit(0)


# --- ClientThread (Handles both Bluetooth and Logic Test modes) ---
class ClientThread(QThread):
    def __init__(self, target_address, file_path, signals, is_logic_test=False, client_queue=None, server_queue=None):
        super().__init__()
        self.target_address = target_address  # Needed for BT mode identification
        self.file_path = file_path  # Full path to the file being sent
        self.signals = signals  # Signal object for GUI communication
        self.is_logic_test = is_logic_test  # Flag for operation mode
        # Queues for Logic Test mode
        self.client_queue = client_queue  # Queue client writes data to (server reads from)
        self.server_queue = server_queue  # Queue client reads confirmation from (server writes to)
        # Bluetooth specific
        self.sock = None  # Socket for Bluetooth connection
        self.running = True  # Flag to allow stopping the transfer prematurely

    def stop(self):
        """Signals the thread to stop and cleans up resources."""
        self.signals.log_message.emit("Client stop requested.")
        self.running = False  # Signal the main loops to exit
        # Close socket if it exists (BT mode)
        if self.sock:
            try:
                # Attempt graceful shutdown
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
                self.signals.log_message.emit("Client socket closed.")
            except Exception:
                pass
            self.sock = None
        # No need to unblock queues here, server handles its own queue reads/timeouts

    def run(self):
        """Main execution method, calls mode-specific run methods."""
        # Check prerequisites
        if not cryptography_available or not AES_KEY:
            self.signals.log_message.emit("Error: Cryptography not available or key missing. Cannot send file.")
            self.signals.transfer_complete.emit(False, "Send failed: Cryptography setup error")
            return

        # Choose execution path based on mode
        if self.is_logic_test:
            self.run_logic_test_client()
        elif bluetooth:  # Only run Bluetooth client if library is available
            self.run_bluetooth_client()
        else:
            # If BT library missing and not in logic test mode
            self.signals.log_message.emit("Bluetooth library not available. Cannot send via Bluetooth.")
            self.signals.transfer_complete.emit(False, "Send failed: Bluetooth unavailable")

        # Final status update (only relevant for BT mode, logic test sets its own final status)
        if not self.is_logic_test:
            # Ensure status reflects disconnection after attempt
            self.signals.connection_status.emit("Status: Disconnected")

    def run_logic_test_client(self):
        """Client logic for Logic Test mode using queues."""
        self.signals.log_message.emit("Starting file transfer (Logic Test mode)...")
        self.signals.connection_status.emit("Status: Processing Logic Test")
        self.signals.progress_update.emit(0)  # Reset progress bar

        try:
            # Ensure queues were provided
            if not self.client_queue or not self.server_queue:
                raise ValueError("Queues not provided for Logic Test mode")

            # Get file info
            filename = os.path.basename(self.file_path)
            filesize = os.path.getsize(self.file_path)
            if filesize == 0:
                self.signals.log_message.emit("Warning: Selected file is empty.")

            # --- Prepare Encryption ---
            nonce = os.urandom(12)  # Generate unique nonce for this transfer (96 bits recommended for GCM)
            aesgcm = AESGCM(AES_KEY)

            # --- 1. Send Metadata via Queue ---
            metadata = {'filename': filename, 'filesize': filesize, 'nonce': nonce.hex()}
            metadata_json = json.dumps(metadata)
            # Put the encoded metadata onto the queue for the server thread
            self.client_queue.put(metadata_json.encode('utf-8'))
            self.signals.log_message.emit(f"Sent metadata (Logic Test): {metadata_json}")

            # --- Wait for Confirmation from Server ---
            try:
                # Block and wait for 'OK' confirmation from the server queue
                confirmation = self.server_queue.get(timeout=10.0)  # 10 second timeout
                if confirmation != b'OK':
                    # If confirmation is not OK, abort the transfer
                    raise ConnectionAbortedError(
                        f"Server did not confirm metadata (Logic Test). Response: {confirmation.decode(errors='ignore')}")
                self.signals.log_message.emit("Server confirmed metadata (Logic Test). Starting file send...")
            except queue.Empty:
                # If timeout occurs waiting for confirmation
                raise TimeoutError("Timeout waiting for server confirmation (Logic Test)")

            # --- 2. Send File Data (Encrypted) via Queue ---
            bytes_sent = 0
            start_time = time.time()
            # Open the file for reading in binary mode
            with open(self.file_path, 'rb') as f:
                while self.running:  # Check running flag allows stopping mid-transfer
                    chunk = f.read(BUFFER_SIZE)  # Read a chunk from the file
                    if not chunk:
                        break  # End of file reached

                    # Encrypt the chunk (AESGCM includes the authentication tag)
                    encrypted_chunk_with_tag = aesgcm.encrypt(nonce, chunk, None)  # No associated data
                    # Put the encrypted chunk onto the queue for the server
                    self.client_queue.put(encrypted_chunk_with_tag)

                    # Update progress based on original chunk size
                    bytes_sent += len(chunk)
                    if filesize > 0:
                        progress = int(100 * bytes_sent / filesize)
                        self.signals.progress_update.emit(progress)
                    else:
                        self.signals.progress_update.emit(100)  # Handle zero-byte file

                    # Optional small sleep to prevent overwhelming the queue/server thread instantly
                    # This can simulate network latency or just yield control briefly.
                    # time.sleep(0.001)

            # --- Check if Stopped ---
            if not self.running:
                self.signals.log_message.emit("Transfer stopped by user (Logic Test).")
                # Signal server that transfer is aborted (optional, server might just timeout)
                try:
                    self.client_queue.put(None)  # Send sentinel if stopped
                except:
                    pass
                self.signals.transfer_complete.emit(False, "Send cancelled")
                return  # Exit the function

            # --- Transfer Complete (Logic Test) ---
            end_time = time.time()
            duration = end_time - start_time
            transfer_speed = (filesize / duration / 1024) if duration > 0 else 0  # KB/s

            self.signals.progress_update.emit(100)  # Ensure progress hits 100%
            self.signals.log_message.emit(
                f"File '{filename}' sent (Logic Test) in {duration:.2f}s ({transfer_speed:.2f} KB/s).")
            # Signal success to the GUI
            self.signals.transfer_complete.emit(True, f"Sent '{filename}' (Logic Test)")

        # --- Error Handling (Logic Test) ---
        except (ValueError, ConnectionAbortedError, TimeoutError, OSError) as e:  # Catch expected errors
            self.signals.log_message.emit(f"Error during Logic Test send: {e}")
            self.signals.connection_status.emit("Status: Error during Logic Test")
            self.signals.transfer_complete.emit(False, f"Logic Test send failed: {e}")
            # Signal server about failure? Optional. Sending None might help server exit faster.
            try:
                self.client_queue.put(None)
            except:
                pass
        except Exception as e:
            # Catch any other unexpected errors
            self.signals.log_message.emit(f"Unexpected error during Logic Test send: {e}")
            self.signals.log_message.emit(traceback.format_exc())  # Log full traceback
            self.signals.connection_status.emit("Status: Error during Logic Test")
            self.signals.transfer_complete.emit(False, f"Logic Test send failed: {e}")
            # Signal server about failure
            try:
                self.client_queue.put(None)
            except:
                pass
        finally:
            # --- Final Cleanup (Logic Test) ---
            # No socket to close in this mode
            self.signals.connection_status.emit("Status: Logic Test Finished")
            self.signals.progress_update.emit(0)  # Reset progress bar

    def run_bluetooth_client(self):
        """Client logic for Bluetooth mode."""
        target_desc = self.target_address  # Use the address passed during init
        self.signals.log_message.emit(f"Attempting Bluetooth connection to {target_desc}...")
        self.signals.connection_status.emit(f"Status: Connecting to {target_desc}...")
        self.signals.progress_update.emit(0)  # Reset progress bar

        try:
            # --- Find Bluetooth Service ---
            self.signals.log_message.emit(f"Searching for service {SERVICE_UUID} on {target_desc}...")
            # Look for the specific service UUID on the target device address
            service_matches = bluetooth.find_service(uuid=SERVICE_UUID, address=target_desc)

            # Check if the service was found
            if not service_matches:
                # If service not found, raise an error
                raise ConnectionRefusedError(
                    f"Could not find the Secure File Transfer service on {target_desc}. Ensure the server app is running on the target device.")

            # --- Extract Connection Details ---
            first_match = service_matches[0]
            port = first_match["port"]  # RFCOMM channel/port
            host = target_desc  # Target device address
            # Get service name (optional, for logging)
            service_name_str = first_match.get('name', 'Unknown Service')  # Use .get for safety
            if isinstance(service_name_str, bytes):
                service_name_str = service_name_str.decode('utf-8', errors='replace')

            self.signals.log_message.emit(f"Found service \"{service_name_str}\" on {host} channel {port}")

            # --- Connect Socket ---
            # Create a Bluetooth RFCOMM socket
            self.sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            # Set a timeout for the connection attempt (e.g., 20 seconds)
            self.sock.settimeout(20.0)
            self.signals.log_message.emit(f"Connecting to {host} channel {port}...")
            # Attempt to connect to the host and port
            self.sock.connect((host, port))
            # Disable the timeout after successful connection for data transfer phase
            self.sock.settimeout(1.0)

            self.signals.log_message.emit("Bluetooth connection successful.")
            self.signals.connection_status.emit(f"Status: Connected to {target_desc}")

            # --- Start File Transfer ---
            # Get file info
            filename = os.path.basename(self.file_path)
            filesize = os.path.getsize(self.file_path)
            if filesize == 0:
                self.signals.log_message.emit("Warning: Selected file is empty.")

            # Prepare encryption
            nonce = os.urandom(12)  # Unique nonce for this transfer
            aesgcm = AESGCM(AES_KEY)

            # --- 1. Send Metadata ---
            metadata = {'filename': filename, 'filesize': filesize, 'nonce': nonce.hex()}
            metadata_json = json.dumps(metadata)
            # Send metadata over the Bluetooth socket
            self.sock.send(metadata_json.encode('utf-8'))
            self.signals.log_message.emit(f"Sent metadata: {metadata_json}")

            # --- Wait for Confirmation ---
            # Set timeout for receiving confirmation
            self.sock.settimeout(15.0)
            confirmation = self.sock.recv(BUFFER_SIZE)  # Expect 'OK'
            self.sock.settimeout(1.0)  # Disable timeout

            # Check confirmation
            if confirmation != b'OK':
                raise ConnectionAbortedError(
                    f"Receiver did not confirm metadata. Response: {confirmation.decode(errors='ignore')}")
            self.signals.log_message.emit("Receiver confirmed metadata. Starting file send...")

            # --- 2. Send File Data (Encrypted) ---
            bytes_sent = 0
            start_time = time.time()
            # Open file for reading in binary mode
            with open(self.file_path, 'rb') as f:
                while self.running:  # Check running flag
                    chunk = f.read(BUFFER_SIZE)  # Read chunk
                    if not chunk: break  # End of file

                    # Encrypt chunk
                    encrypted_chunk_with_tag = aesgcm.encrypt(nonce, chunk, None)
                    # Send encrypted chunk over socket (use sendall for reliability)
                    # self.sock.sendall(encrypted_chunk_with_tag)
                    self.sock.send(encrypted_chunk_with_tag)

                    # Update progress
                    bytes_sent += len(chunk)
                    if filesize > 0:
                        progress = int(100 * bytes_sent / filesize)
                        self.signals.progress_update.emit(progress)
                    else:
                        self.signals.progress_update.emit(100)  # Zero-byte file

            # --- Check if Stopped ---
            if not self.running:
                self.signals.log_message.emit("Transfer stopped by user (Bluetooth).")
                self.signals.transfer_complete.emit(False, "Send cancelled")
                # Socket will be closed in the finally block
                return  # Exit function

            # --- Transfer Complete (Bluetooth) ---
            end_time = time.time()
            duration = end_time - start_time
            transfer_speed = (filesize / duration / 1024) if duration > 0 else 0  # KB/s

            self.signals.progress_update.emit(100)  # Ensure 100%
            self.signals.log_message.emit(
                f"File '{filename}' sent successfully to {target_desc} in {duration:.2f}s ({transfer_speed:.2f} KB/s).")
            # Signal success to GUI
            self.signals.transfer_complete.emit(True, f"Sent '{filename}' to {target_desc}")

        # --- Error Handling (Bluetooth) ---
        except bluetooth.btcommon.BluetoothError as e:
            # Handle specific Bluetooth errors more gracefully
            error_msg = str(e)
            if "unreachable network" in error_msg.lower() or \
                    "host is down" in error_msg.lower():
                error_msg = f"Host {target_desc} is unreachable. (Check power/range/firewall?)"
            elif "timed out" in error_msg.lower():
                error_msg = "Connection timed out. Ensure device is reachable and service is running."
            elif "connection refused" in error_msg.lower():
                error_msg = "Connection refused. Ensure the server application is running on the target device."
            self.signals.log_message.emit(f"Bluetooth Error: {error_msg}")
            self.signals.connection_status.emit(f"Status: Connection Failed (BT)")
            self.signals.transfer_complete.emit(False, f"Connection Failed: {error_msg}")
        except (ConnectionRefusedError, ConnectionAbortedError, TimeoutError, OSError) as e:
            # Handle other connection/file related errors
            self.signals.log_message.emit(f"Connection/File Error: {e}")
            self.signals.connection_status.emit("Status: Connection Error")
            self.signals.transfer_complete.emit(False, f"Transfer Error: {e}")
        except Exception as e:
            # Catch any other unexpected errors
            self.signals.log_message.emit(f"Error during sending to {target_desc}: {e}")
            self.signals.log_message.emit(traceback.format_exc())  # Log traceback
            self.signals.connection_status.emit("Status: Error during transfer")
            self.signals.transfer_complete.emit(False, f"Send failed: {e}")
        finally:
            # --- Final Cleanup (Bluetooth) ---
            if self.sock:
                try:
                    self.sock.close()  # Ensure socket is closed
                except Exception:
                    pass
                self.sock = None
            # Reset progress bar regardless of outcome
            self.signals.progress_update.emit(0)
            # Status is set to Disconnected at the start of the next run or when app closes


# --- Main Application Window ---
class BluetoothTransferApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        # --- Check Prerequisites ---
        # Ensure cryptography library is available and key was derived
        if not cryptography_available:
            # Show critical error and exit if cryptography is missing
            QMessageBox.critical(self, "Cryptography Error",
                                 "Cryptography library is missing or failed to initialize.\n"
                                 "File transfer requires 'cryptography'. Please install it:\n\n"
                                 "pip install cryptography\n\nApplication will exit.")
            sys.exit(1)
        if not AES_KEY:
            # Show critical error and exit if key derivation failed
            QMessageBox.critical(self, "Cryptography Error",
                                 "Failed to derive AES key from password/salt.\n"
                                 "Cannot proceed with encryption/decryption.\nApplication will exit.")
            sys.exit(1)

        # --- Load UI ---
        try:
            # Construct path to UI file relative to this script file
            script_dir = os.path.dirname(__file__)
            ui_file_path = os.path.join(script_dir, "new_main_page.ui")
            # Fallback to current working directory if not found next to script
            if not os.path.exists(ui_file_path):
                ui_file_path = "new_main_page.ui"
            # Load the UI from the .ui file
            uic.loadUi(ui_file_path, self)
        except FileNotFoundError:
            QMessageBox.critical(self, "UI Error",
                                 f"Could not find the UI file: new_main_page.ui\n"
                                 f"Please ensure it's in the same directory as the script ('{script_dir}') or the current working directory.")
            sys.exit(1)
        except Exception as e:
            # Handle other UI loading errors
            QMessageBox.critical(self, "UI Load Error", f"Failed to load UI: {e}\n{traceback.format_exc()}")
            sys.exit(1)

        # Set window title
        self.setWindowTitle("Secure File Transfer (Bluetooth/Logic Test)")

        # --- Logic Test Checkbox Handling ---
        # Ensure the checkbox exists (either from UI file or added programmatically)
        if not hasattr(self, 'logicTestCheckBox'):  # Check if loaded from .ui file
            # If not in UI, create and add it
            self.logicTestCheckBox = QCheckBox("Logic Test (No Bluetooth)")
            self.logicTestCheckBox.setObjectName("logicTestCheckBox")  # Set object name
            self.logicTestCheckBox.setToolTip("Check this to test file logic without using Bluetooth.")
            # Try adding it to the connection group box layout
            if hasattr(self, 'connectionLayout'):
                # Add to grid layout (row 4, spanning 2 columns)
                self.connectionLayout.addWidget(self.logicTestCheckBox, 4, 0, 1, 2)
            elif hasattr(self, 'mainLayout'):
                # Fallback: Add to main layout if connectionLayout missing
                self.mainLayout.insertWidget(1, self.logicTestCheckBox)  # Insert near top
            else:
                # Warning if no suitable layout found
                print("Warning: Could not find a suitable layout to add Logic Test checkbox.")
        else:
            # If loaded from UI, ensure text/tooltip are set correctly
            self.logicTestCheckBox.setText("Logic Test (No Bluetooth)")
            self.logicTestCheckBox.setToolTip("Check this to test file logic without using Bluetooth.")

        # --- Initialize Workers and State ---
        self.signals = WorkerSignals()  # Communication signals between threads and GUI
        # Queues for logic testing mode
        self.client_to_server_queue = queue.Queue()
        self.server_to_client_queue = queue.Queue()
        # Thread references
        self.scanner_thread = None
        self.server_thread = None
        self.client_thread = None

        # Application state variables
        self.selected_device_address = None  # MAC address of selected BT device
        self.selected_file_path = None  # Full path of file selected to send
        self.is_transfer_active = False  # Flag indicating if send/receive is running
        self.local_bt_address = None  # This machine's BT address

        # --- Connect Signals ---
        # Connect signals from worker threads to GUI update slots
        self.signals.device_discovered.connect(self.add_device_to_list)
        self.signals.scan_finished.connect(self.on_scan_finished)
        self.signals.connection_status.connect(self.update_status_label)
        self.signals.log_message.connect(self.append_log)
        self.signals.progress_update.connect(self.update_progress_bar)
        self.signals.transfer_complete.connect(self.on_transfer_complete)
        # self.signals.enable_send_button.connect(self.sendButton.setEnabled) # Can be used by threads if needed
        self.signals.clear_device_list.connect(self.deviceListWidget.clear)
        self.signals.set_file_path.connect(self.filePathLineEdit.setText)

        # Connect GUI widget signals (user actions) to handler methods
        self.scanButton.clicked.connect(self.start_scan)
        # The 'Connect' button from the UI is likely unused in this direct transfer workflow.
        # Disable or hide it to avoid confusion.
        if hasattr(self, 'connectButton'):
            self.connectButton.setEnabled(False)
            # self.connectButton.setVisible(False) # Optionally hide completely
        self.selectFileButton.clicked.connect(self.select_file)
        self.sendButton.clicked.connect(self.send_file)
        # Signal emitted when selection changes in the device list
        self.deviceListWidget.itemSelectionChanged.connect(self.on_device_selected)
        # Signal emitted when the logic test checkbox state changes
        self.logicTestCheckBox.stateChanged.connect(self.on_logic_test_changed)

        # --- Initial UI State ---
        self.logTextEdit.setReadOnly(True)
        self.filePathLineEdit.setReadOnly(True)  # Display only, set via button
        self.progressBar.setValue(0)
        self.progressBar.setTextVisible(True)  # Ensure percentage text is shown
        self.sendButton.setEnabled(False)  # Disabled until file and target are selected
        self.statusLabel.setText("Status: Initializing...")
        # Set initial enabled/disabled state of controls based on mode
        self.update_ui_for_mode()

        # --- Bluetooth Initialization ---
        # Attempt to get local BT address if library is available
        if bluetooth:
            self.get_local_address()
        else:
            self.append_log("Bluetooth library not found. Bluetooth features disabled.")
            # Optionally force Logic Test mode if BT is unavailable
            # self.logicTestCheckBox.setChecked(True)
            # self.logicTestCheckBox.setEnabled(False) # Prevent unchecking if BT missing

        # --- Start Server Thread ---
        # Start the server thread automatically on application launch
        self.start_server()

    def get_local_address(self):
        """Reads and stores the local Bluetooth address (if BT available)."""
        if not bluetooth: return  # Skip if BT lib missing
        try:
            # Attempt to read the local Bluetooth adapter's MAC address
            addr_tuple = bluetooth.read_local_bdaddr()
            if addr_tuple:
                self.local_bt_address = addr_tuple[0]
                self.append_log(f"Local Bluetooth Address: {self.local_bt_address}")
            else:
                # This can happen if the adapter is disabled or drivers have issues
                self.append_log("Warning: Could not read local Bluetooth address (read_local_bdaddr returned None).")
                # Don't show popup here, let server thread handle its own checks if needed
        except Exception as e:
            # Log any errors encountered reading the address
            self.append_log(f"Error reading local Bluetooth address: {e}")
            # Don't show popup here

    def start_server(self):
        """Starts the ServerThread if not already running."""
        # Prevent starting multiple server threads
        if self.server_thread and self.server_thread.isRunning():
            self.append_log("Server thread is already running.")
            # Optional: Ensure its mode matches checkbox state if started externally?
            # is_test_mode = self.logicTestCheckBox.isChecked()
            # self.server_thread.set_logic_test_mode(is_test_mode)
            return

        self.append_log("Starting server thread...")
        # Create a new ServerThread instance, passing signals and queues
        self.server_thread = ServerThread(self.signals, self.client_to_server_queue, self.server_to_client_queue)
        # Set the mode based on the current checkbox state BEFORE starting
        is_test_mode = self.logicTestCheckBox.isChecked()
        self.server_thread.set_logic_test_mode(is_test_mode)
        # Start the thread's execution (calls run() method)
        self.server_thread.start()

    def start_scan(self):
        """Starts the Bluetooth device discovery process."""
        # Prevent scanning if a transfer is active
        if self.is_transfer_active:
            self.append_log("Cannot scan during active transfer.")
            return
        # Prevent scanning if in logic test mode
        if self.logicTestCheckBox.isChecked():
            QMessageBox.information(self, "Scan Disabled", "Scanning is disabled in Logic Test mode.")
            return
        # Prevent scanning if Bluetooth library is unavailable
        if not bluetooth:
            QMessageBox.warning(self, "Scan Error", "Bluetooth library not available. Cannot scan.")
            return

        # Prevent starting multiple scans concurrently
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.append_log("Scan already in progress.")
            return

        # Update UI for scanning state
        self.scanButton.setEnabled(False)  # Disable scan button during scan
        self.deviceListWidget.clear()  # Clear previous results
        self.selected_device_address = None  # Reset selection
        self.update_send_button_state()  # Send button depends on selection

        # Create and start the scanner thread
        self.scanner_thread = ScannerThread(self.signals)
        self.scanner_thread.start()

    def on_scan_finished(self):
        """Called when the ScannerThread finishes."""
        # Re-enable scan button unless in logic test mode or a transfer is active
        if not self.logicTestCheckBox.isChecked() and not self.is_transfer_active:
            self.scanButton.setEnabled(True)

    def add_device_to_list(self, name, address):
        """Adds a discovered Bluetooth device to the UI list widget."""
        # Optional: Avoid adding duplicate entries
        for i in range(self.deviceListWidget.count()):
            item = self.deviceListWidget.item(i)
            if item.data(Qt.UserRole) == address:
                # self.append_log(f"Device {address} already in list.")
                return  # Skip adding if address already exists

        # Create list item text (Name (Address))
        item_text = f"{name} ({address})"
        item = QtWidgets.QListWidgetItem(item_text)
        # Store the device address directly with the list item for later retrieval
        item.setData(Qt.UserRole, address)
        self.deviceListWidget.addItem(item)

    def on_device_selected(self):
        """Handles the user selecting a device in the list widget."""
        # This is only relevant when NOT in logic test mode
        if self.logicTestCheckBox.isChecked():
            self.selected_device_address = None  # Ensure no address selected in test mode
        else:
            # Get the currently selected items (should be single selection mode)
            selected_items = self.deviceListWidget.selectedItems()
            if selected_items:
                # Retrieve the address stored in the selected item's UserRole data
                selected_item = selected_items[0]
                self.selected_device_address = selected_item.data(Qt.UserRole)
                self.append_log(f"Selected device: {selected_item.text()}")
            else:
                # No item selected
                self.selected_device_address = None
        # Update the send button state based on the selection (or lack thereof)
        self.update_send_button_state()

    # *** MODIFIED METHOD ***
    def on_logic_test_changed(self, state):
        """Handles changes to the logic test checkbox state. Stops and restarts server."""
        is_test_mode = (state == Qt.Checked)
        self.update_ui_for_mode()  # Update UI elements first (disable/enable scan, list)

        self.append_log(f"Mode change requested to: {'Logic Test' if is_test_mode else 'Bluetooth'}")

        # --- Stop existing server thread ---
        # It's crucial to stop the current server thread before starting a new one
        # because the running thread is likely blocked in the wrong execution path (BT accept or queue get).
        if self.server_thread and self.server_thread.isRunning():
            self.append_log("Stopping existing server thread for mode change...")
            self.server_thread.stop()  # Signal the thread to stop
            # Wait briefly for the thread to finish. This might block the GUI slightly.
            # A more complex solution would use signals to know when the thread has truly stopped.
            if not self.server_thread.wait(1500):  # Wait up to 1.5 seconds
                self.append_log("Warning: Server thread did not stop quickly during mode change.")
                # Consider disabling UI further if thread doesn't stop, or force terminate (riskier)
            else:
                self.append_log("Existing server thread stopped.")
            self.server_thread = None  # Clear the reference to the stopped thread object

        # --- Start new server thread in the correct mode ---
        # This will create a new ServerThread instance which will check the
        # logicTestCheckBox state when its run() method begins.
        self.start_server()

        # --- Update UI and state after mode change ---
        if is_test_mode:
            self.append_log("Logic Test mode enabled. Send will use internal queues.")
            self.deviceListWidget.clearSelection()  # Ensure no BT device selected
            self.selected_device_address = None
        else:
            self.append_log("Logic Test mode disabled. Select a device for Bluetooth transfer.")
            # Trigger re-evaluation of selection state if list has items
            self.on_device_selected()

        # Update send button state based on the new mode and other conditions
        self.update_send_button_state()

    def update_ui_for_mode(self):
        """Enables/disables UI elements based on Logic Test mode and BT availability."""
        is_test_mode = self.logicTestCheckBox.isChecked()
        is_bt_available = bool(bluetooth)  # Check if bluetooth module was imported

        # Scan button: Enabled only if BT is available, not in test mode, and no transfer active
        self.scanButton.setEnabled(is_bt_available and not is_test_mode and not self.is_transfer_active)
        # Device list: Enabled only if BT is available and not in test mode
        # (Selection is possible even during transfer, though sending is blocked)
        self.deviceListWidget.setEnabled(is_bt_available and not is_test_mode)

        # If switching to test mode, clear any existing BT device selection
        if is_test_mode:
            self.deviceListWidget.clearSelection()

    def select_file(self):
        """Opens a file dialog for the user to select a file to send."""
        # Prevent changing file during an active transfer
        if self.is_transfer_active:
            self.append_log("Cannot select file during active transfer.")
            return

        # Suggest starting directory based on previously selected file or user's home dir
        start_dir = os.path.dirname(self.selected_file_path) if self.selected_file_path else os.path.expanduser("~")
        # Open file dialog
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send", start_dir)

        # If user selected a file (didn't cancel)
        if file_path:
            # Basic check for file readability
            try:
                with open(file_path, 'rb') as f_test:
                    f_test.read(1)  # Try reading one byte to check permissions
                # Store the selected path and update the UI text field
                self.selected_file_path = file_path
                self.filePathLineEdit.setText(file_path)
                self.append_log(f"Selected file: {file_path}")
            except Exception as e:
                # Handle errors accessing the file (e.g., permissions)
                self.append_log(f"Error accessing file: {e}")
                QMessageBox.warning(self, "File Error", f"Cannot read selected file:\n{e}")
                # Clear selection if file is inaccessible
                self.selected_file_path = None
                self.filePathLineEdit.setText("")
        else:
            # User cancelled the dialog
            # Keep previous selection (if any)
            self.append_log("File selection cancelled.")

        # Update send button state based on whether a valid file is now selected
        self.update_send_button_state()

    def send_file(self):
        """Initiates the file sending process in the appropriate mode."""
        # Prevent starting a new transfer if one is already active
        if self.is_transfer_active:
            self.append_log("Error: Another transfer is already in progress.")
            QMessageBox.warning(self, "Transfer Busy", "Please wait for the current transfer to complete.")
            return
        # Sanity check: Ensure previous client thread isn't lingering (shouldn't happen ideally)
        if self.client_thread and self.client_thread.isRunning():
            self.append_log("Error: Previous client thread is unexpectedly still running. Please wait.")
            # Attempt to clean up previous thread? Risky. Better to prevent starting.
            return

        # Determine mode and target
        is_logic_test = self.logicTestCheckBox.isChecked()
        target_addr = None  # Only used for BT mode

        # --- Target Validation ---
        if not is_logic_test:
            # Bluetooth Mode Checks
            if not bluetooth:
                QMessageBox.critical(self, "Bluetooth Error",
                                     "Bluetooth library not available. Cannot send via Bluetooth.")
                return
            if not self.selected_device_address:
                # Must have selected a device from the list
                self.append_log("Error: No target device selected for Bluetooth transfer.")
                QMessageBox.warning(self, "Send Error", "Please select a device from the list.")
                return
            target_addr = self.selected_device_address
            self.append_log(f"Initiating Bluetooth transfer to {target_addr}...")
        else:
            # Logic Test Mode
            self.append_log("Initiating internal file transfer (Logic Test mode)...")

        # --- File Validation ---
        if not self.selected_file_path:
            self.append_log("Error: No file selected to send.")
            QMessageBox.warning(self, "Send Error", "Please select a file to send.")
            return
        # Check if file exists and is accessible
        if not os.path.exists(self.selected_file_path):
            self.append_log(f"Error: Selected file not found: {self.selected_file_path}")
            QMessageBox.critical(self, "Send Error", f"File not found:\n{self.selected_file_path}")
            # Clear invalid path from state and UI
            self.selected_file_path = None
            self.filePathLineEdit.setText("")
            self.update_send_button_state()
            return
        try:
            # Check file size (optional, e.g., prevent sending huge files)
            filesize = os.path.getsize(self.selected_file_path)
            # if filesize > MAX_ALLOWED_SIZE: ... error ...
        except OSError as e:
            # Handle error getting file size
            self.append_log(f"Error accessing file properties: {e}")
            QMessageBox.critical(self, "File Error", f"Cannot access file properties:\n{e}")
            return

        # --- Start Transfer ---
        self.is_transfer_active = True  # Set flag
        self.update_ui_for_transfer_state()  # Disable buttons appropriately

        self.append_log(f"Starting send process for {os.path.basename(self.selected_file_path)}")
        # Create and start the ClientThread, passing necessary info
        self.client_thread = ClientThread(
            target_address=target_addr,  # Pass address (used only in BT mode)
            file_path=self.selected_file_path,
            signals=self.signals,
            is_logic_test=is_logic_test,  # Pass the mode flag
            # Pass the queues (used only in logic test mode)
            client_queue=self.client_to_server_queue if is_logic_test else None,
            server_queue=self.server_to_client_queue if is_logic_test else None
        )
        self.client_thread.start()  # Start the client thread execution

    def update_send_button_state(self):
        """Enables/disables the Send button based on current state."""
        # Always disable if a transfer is active
        if self.is_transfer_active:
            self.sendButton.setEnabled(False)
            return

        # Check if a valid file path is selected
        file_selected = bool(self.selected_file_path) and os.path.exists(self.selected_file_path)
        # Check current mode
        is_logic_test = self.logicTestCheckBox.isChecked()
        # Determine if a valid target is set for the current mode
        # Target is valid if (in logic test mode) OR (in BT mode AND a device address is selected)
        target_valid = is_logic_test or (not is_logic_test and bool(self.selected_device_address))

        # Enable send button only if a file is selected AND the target is valid for the mode
        can_send = file_selected and target_valid
        self.sendButton.setEnabled(can_send)

    def update_ui_for_transfer_state(self):
        """Enable/disable controls based on whether a transfer is active."""
        # These buttons are always disabled during transfer
        self.sendButton.setEnabled(not self.is_transfer_active)
        self.selectFileButton.setEnabled(not self.is_transfer_active)
        # Prevent changing mode during transfer
        self.logicTestCheckBox.setEnabled(not self.is_transfer_active)

        # Scan button and device list state depends on mode as well
        is_test_mode = self.logicTestCheckBox.isChecked()
        is_bt_available = bool(bluetooth)
        # Enable scan only if BT available, not test mode, and not transferring
        self.scanButton.setEnabled(is_bt_available and not is_test_mode and not self.is_transfer_active)
        # Enable device list only if BT available and not test mode (allow selection viewing even during transfer?)
        self.deviceListWidget.setEnabled(is_bt_available and not is_test_mode)

    def update_status_label(self, status):
        """Updates the status label text at the bottom."""
        self.statusLabel.setText(status)
        # Could potentially update self.is_transfer_active based on status messages too,
        # but on_transfer_complete is more reliable for end state.

    def append_log(self, message):
        """Appends a message to the log text edit with a timestamp."""
        # Ensure message is a string
        if not isinstance(message, str):
            message = str(message)
        # Append with timestamp
        current_time = time.strftime('%H:%M:%S')
        self.logTextEdit.append(f"[{current_time}] {message}")
        self.logTextEdit.ensureCursorVisible()  # Auto-scroll to the bottom

    def update_progress_bar(self, value):
        """Updates the progress bar value."""
        # Clamp value between 0 and 100
        value = max(0, min(100, value))
        self.progressBar.setValue(value)

    def on_transfer_complete(self, success, message):
        """Called when either ClientThread or ServerThread signals transfer end."""
        # Mark transfer as inactive
        self.is_transfer_active = False
        self.append_log(f"Transfer complete signal received: Success={success}, Message='{message}'")

        # Show popup message box to user
        if success:
            QMessageBox.information(self, "Transfer Complete", message)
            # Optionally clear file path only on successful send
            # self.selected_file_path = None
            # self.filePathLineEdit.setText("")
        else:
            # Show warning on failure
            QMessageBox.warning(self, "Transfer Failed", message)

        # Reset progress bar and re-evaluate UI state (re-enable buttons)
        self.progressBar.setValue(0)
        self.update_ui_for_transfer_state()  # Re-enable controls based on mode
        self.update_send_button_state()  # Re-evaluate send button specifically

    def closeEvent(self, event):
        """Handles application closing event."""
        self.append_log("Close event received. Shutting down threads...")
        # --- Stop Threads Gracefully ---
        # Stop scanner thread if running
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.append_log("Stopping scanner thread...")
            self.scanner_thread.quit()  # Ask thread to exit event loop if applicable
            if not self.scanner_thread.wait(1000):  # Wait 1 sec
                self.append_log("Scanner thread did not stop gracefully, terminating.")
                self.scanner_thread.terminate()  # Force stop if needed

        # Stop client thread if running
        if self.client_thread and self.client_thread.isRunning():
            self.append_log("Stopping client thread...")
            self.client_thread.stop()  # Use custom stop method
            if not self.client_thread.wait(2000):  # Wait 2 secs
                self.append_log("Client thread did not stop gracefully, terminating.")
                self.client_thread.terminate()

        # Stop server thread if running
        if self.server_thread and self.server_thread.isRunning():
            self.append_log("Stopping server thread...")
            self.server_thread.stop()  # Use custom stop method
            if not self.server_thread.wait(2000):  # Wait 2 secs
                self.append_log("Server thread did not stop gracefully.")
                # Avoid terminating server if possible, as it might leave resources open
                # Consider logging a more severe warning here.

        self.append_log("Cleanup complete. Exiting.")
        event.accept()  # Allow the window to close


# --- Main Execution Block ---
if __name__ == "__main__":
    # Initialize the Qt Application
    app = QtWidgets.QApplication(sys.argv)

    # --- Initial Bluetooth Check ---
    # Perform a basic check if the Bluetooth library was imported successfully
    # to provide early user feedback if Bluetooth features will be unavailable.
    bt_check_passed = False
    if bluetooth:
        try:
            # Try reading the local adapter address as a basic check
            addr_tuple = bluetooth.read_local_bdaddr()
            # Sometimes reading immediately fails, try a short delay and retry
            if not addr_tuple:
                print("Warning: read_local_bdaddr() returned None. Retrying after 1s...", file=sys.stderr)
                time.sleep(1)
                addr_tuple = bluetooth.read_local_bdaddr()

            if addr_tuple:
                print(f"Local Bluetooth Address found: {addr_tuple[0]}")
                bt_check_passed = True
            else:
                # If still fails, show a warning but allow app to continue for Logic Test mode
                print("ERROR: Could not read local Bluetooth address after retry.", file=sys.stderr)
                QMessageBox.warning(None, "Bluetooth Warning",
                                    "Could not read local Bluetooth address.\n"
                                    "Bluetooth features might be limited or unavailable.\n"
                                    "Ensure Bluetooth is enabled and drivers are working.\n\n"
                                    "Logic Test mode should still function.")
                # Allow app to continue, but BT mode might fail later
        except OSError as e:
            # Handle OS-level errors (e.g., adapter disabled, no adapter)
            print(f"ERROR initializing Bluetooth: {e}", file=sys.stderr)
            QMessageBox.critical(None, "Bluetooth Error",
                                 f"Could not initialize Bluetooth adapter: {e}\n\n"
                                 "Please ensure Bluetooth is turned on and drivers are installed.\n"
                                 "Bluetooth functionality will be unavailable.\n\n"
                                 "Logic Test mode should still function.")
            # Allow app to continue for logic testing
        except Exception as e:
            # Catch any other unexpected errors during the check
            print(f"An unexpected error occurred during Bluetooth check: {e}", file=sys.stderr)
            print(traceback.format_exc(), file=sys.stderr)
            QMessageBox.critical(None, "Startup Error", f"An unexpected error occurred during Bluetooth check: {e}")
            # Depending on severity, might exit here:
            # sys.exit(1)
    else:
        # If 'bluetooth' is None (import failed)
        print("Bluetooth library not found. Skipping Bluetooth checks.")
        # bt_check_passed remains False

    # --- Cryptography Check ---
    # Ensure crypto library is working before creating the main window
    if not cryptography_available or not AES_KEY:
        # Error message should have been printed earlier if import failed
        print("ERROR: Cryptography prerequisites not met. Exiting.", file=sys.stderr)
        # Show message box again just in case __init__ wasn't reached or user missed console
        if not QtWidgets.QApplication.instance():  # Ensure app exists for msgbox
            _ = QtWidgets.QApplication(sys.argv)  # Create dummy app if needed
        QMessageBox.critical(None, "Prerequisite Error",
                             "Cryptography library missing or key generation failed.\n"
                             "Application cannot run securely. Please check console output.\n\nExiting.")
        sys.exit(1)

    # --- Create and Show Main Window ---
    try:
        window = BluetoothTransferApp()  # Create instance of the main application widget
        window.show()  # Make the window visible
    except Exception as e:
        # Catch critical errors during main window initialization
        print(f"FATAL ERROR creating main window: {e}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        if not QtWidgets.QApplication.instance():  # Ensure app exists for msgbox
            _ = QtWidgets.QApplication(sys.argv)
        QMessageBox.critical(None, "Application Error",
                             f"Failed to create the main application window:\n{e}\n\nExiting.")
        sys.exit(1)

    # --- Start Qt Event Loop ---
    # This starts processing user input, signals, etc.
    # The application will exit when the main window is closed.
    sys.exit(app.exec_())
