# SLPH Semantic Classes Definition

This document defines the set of semantic classes that the SLPH machine learning model will predict. 
These labels provide a high-level understanding of a protocol field's purpose.

### Core Data and Structure

* **Length**
    * **Definition**: A field whose value indicates the size in bytes of another field or the rest of the message.
    * **Example**: The `Content-Length` header in HTTP; the `Total Length` field in an IP header.

* **Checksum**
    * **Definition**: A field used to verify the integrity of the message data against corruption.
    * **Example**: The 16-bit checksum in a TCP header.

* **Constant / Magic Number**
    * **Definition**: A field with a fixed, unchanging value, often used to identify the protocol or a specific file type.
    * **Example**: The `0x89504E47` bytes at the start of a PNG file; The fixed protocol identifier in a proprietary protocol.

* **Payload**
    * **Definition**: The main, often variable-length, data portion of a message, which may contain another protocol or opaque user data.
    * **Example**: The HTML content in a HTTP response; The actual file data in an SMB transfer. 

### Identifiers and Naming

* **Address / Identifier**
    * **Definition**: A field that uniquely identifies a host, user, or resource on a network.
    * **Example**: Source/Destination `IPv4 Address`; `MAC Address`; DHCP `Client Identifier`.

* **Port / Service**
    * **Definition**: A field that identifies a specific application process or service on a host.
    * **Example**: TCP Port `80` for HTTP, UDP Port `53` for DNS.

* **Sequence / ID**
    * **Definition**: A field used to track the order of message or to link requests with responses.
    * **Example**: The `Transaction ID` in a DNS query; the `Sequence Number` in a TCP segment.

### State & Control Flow

* **Opcode / Type / Command ID**
    * **Definition**: A field that specifies the message's purpose, action, or type.
    * **Example**: The `Function Code` in Modbus (e.g., `0x01` for `Read Coils`); the `Opcode` in DNS (Query vs. Response)

* **Status / Error Code**
    * **Definition**: A field indicating the result of a request, such as success, failure, or a specific error condition.
    * **Example**: HTTP Status Codes (`200 OK`, `404 Not Found`); ICMP Type/Code fields.

* **Flags**
    * **Definition**: A bitfield where individual bits act as boolean togglers for different options or states.
    * **Example**: The `SYN`, `ACK`, `FIN` bits in a TCP header.

* **Version**
    * **Definition**: A field that specifies the version of the protocol being used.
    * **Example**: The `IP` version field (`4` or `6`); the version number in a TLS handshake.

* **Timestamp**
    * **Definition**: A field representing a point in time or a duration, often used for synchronization or logging.
    * **Example**: The timestamps used in the NTP protocol for time synchronization.