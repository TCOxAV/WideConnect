# WideConnect Protocol v1

Transport: raw TCP, `TCP_NODELAY` enabled, over a Tailscale tunnel.
All multi-byte integers are **big-endian**.

## Frame layout

| Offset | Size | Field    | Description                              |
|--------|------|----------|------------------------------------------|
| 0      | 2    | Magic    | 0x5743 ("WC"), used to detect desync     |
| 2      | 1    | Version  | Protocol version (currently 0x01)        |
| 3      | 1    | Type     | Message type (see below)                 |
| 4      | 4    | Length   | Payload length in bytes (max 16 MiB)     |
| 8      | N    | Payload  | Type-specific body                       |

Header is a fixed 8 bytes.

## Message types

| Code | Name       | Direction | Purpose                          |
|------|------------|-----------|----------------------------------|
| 0x01 | HELLO      | both      | Handshake: device name, id, caps |
| 0x02 | PING       | both      | Latency probe (8-byte timestamp) |
| 0x03 | PONG       | both      | Echo of PING payload             |
| 0x10 | NOTIFY     | phone→pc  | Notification mirroring           |
| 0x20 | FILE_META  | both      | File transfer start              |
| 0x21 | FILE_CHUNK | both      | File data chunk                  |
| 0x30 | SCREEN     | phone→pc  | Screen frame data                |
| 0xFF | ERROR      | both      | Error code + message             |

## Rules

- A receiver MUST close the connection on bad magic or unsupported version.
- A receiver MUST reject frames whose Length exceeds 16 MiB.
- PING/PONG payload is an 8-byte unsigned nanosecond timestamp; PONG echoes it unchanged.
- Pairing and auth payloads have exact fixed lengths. A receiver MUST close the connection on any other length, and on a PAIR_DECISION byte other than 0 or 1.

## HELLO payload (0x01)

| Offset | Size | Field        | Description                             |
|--------|------|--------------|-----------------------------------------|
| 0      | 16   | DeviceID     | Random, persistent per device           |
| 16     | 1    | Platform     | 1=Linux, 2=Windows, 3=Android           |
| 17     | 4    | Capabilities | Bitmask: 1=Notify, 2=Files, 4=Screen    |
| 21     | 1    | NameLen      | N, max 64                               |
| 22     | N    | Name         | UTF-8 device name                       |

## Handshake

1. The connecting side sends HELLO immediately after the TCP connection opens.
2. The accepting side validates it and replies with its own HELLO.
3. No other frame type is valid until both HELLOs are exchanged.
4. The accepting side MUST close the connection if no valid HELLO arrives within 5 seconds.

| 0x40 | PAIR_REQUEST   | initiator→responder | Commitment (32 bytes)               |
| 0x41 | PAIR_RESPONSE  | responder→initiator | Public key (32) + nonce (16)        |
| 0x42 | PAIR_REVEAL    | initiator→responder | Public key (32) + nonce (16)        |
| 0x43 | PAIR_DECISION  | both                | 1 byte: 1 accept, 0 reject          |
| 0x44 | AUTH_CHALLENGE | both                | Challenge (16 bytes)                |
| 0x45 | AUTH_RESPONSE  | both                | Ed25519 signature (64 bytes)        |