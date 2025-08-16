# NY Protocol PoC

## Overview

This project implements a **Proof-of-Concept (PoC)** for the **NY protocol**, a custom experimental network protocol. It demonstrates **raw socket communication** over Ethernet using a custom **EtherType (0x88B5)**, with **AES-256-CBC encryption** and **SHA-256 HMAC** for secure message exchange.

The protocol defines **three frame types**:

* **DISCOVER** – Device discovery requests
* **ANNOUNCE** – Device announcements
* **DATA** – Encrypted data transmission

This implementation allows sending and receiving messages securely between devices over a local network.

> ⚠️ **Warning:** This is a PoC and **not suitable for production**. It uses a **hardcoded pre-shared key**. For real-world use, implement a proper key exchange, handle replay attacks, validate input, and improve error handling.

## Features

* Raw Ethernet communication with custom EtherType `0x88B5`
* AES-256-CBC encryption for DATA frames
* SHA-256 HMAC for integrity verification
* Device discovery and announcement
* Logging with timestamps and colored output for easier debugging

## Limitations

* Hardcoded 256-bit AES key (insecure)
* Basic error handling and minimal logging
* Supports up to 256 unique MAC addresses
* No protection against replay attacks or advanced network threats
* Tested **only with direct device-to-device connection**; it **may work over a switch**, but this has **not been tested**

## Dependencies

* Linux system
* Root privileges (required for raw socket access)
* **OpenSSL** for cryptography (AES, HMAC, random IV generation)
