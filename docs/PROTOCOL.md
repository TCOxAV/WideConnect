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