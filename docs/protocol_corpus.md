# SLPH Protocol Corpus Plan

This document outlines the initial corpus of network protocols selected for training the SLPH semantic inference model.
The list is chosen to provide a diverse range of protocol types and field semantics to ensure the model is robust.

---
### Target Protocol List

| Protocol | Category | Value for Model | Specification Document |
|---|---|---|---|
| **HTTP/2** | Web | Binary framing, stream IDs, flags | [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html) |
| **TLS 1.3** | Web/Security | Version, extensions, handshake IDs | [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) |
| **DNS** | Infrastructure | Transaction IDs, flags, count fields | [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) |
| **DHCP** | Infrastructure | Options/TLVs, opcodes | [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html) |
| **ICMP** | Infrastructure | Type/Code fields (status class) | [RFC 792](https://www.rfc-editor.org/rfc/rfc792.html) |
| **TCP** | Transport | Sequence #s, ACKs, flags, checksums | [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html) |
| **UDP** | Transport | Length, checksums | [RFC 768](https://www.rfc-editor.org/rfc/rfc768.html) |
| **MQTT** | IoT/Messaging | Lightweight command IDs, lengths | [OASIS Standard v5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) |
| **CoAP** | IoT/Industrial | Binary TLVs, option codes | [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252.html) |
| **Modbus** | Industrial | Function codes, payload separation | [Modbus.org Spec](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf) |
| **SMB** | File Sharing | Complex stateful binary protocol | [MS-SMB2 Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366b4978b) |
| **FTP** | File Sharing/Text | Text-based opcodes, status codes | [RFC 959](https://www.rfc-editor.org/rfc/rfc959.html) |   