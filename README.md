# 🌐 Recursive DNS resolver and authoritative DNS Server

A lightweight DNS implementation in C featuring:

- Recursive DNS resolver
- Authoritative DNS server
- UDP-based DNS communication
- Docker support for testing and deployment

This project aims to develop an educational implementation of the DNS protocol, focusing on recursive name resolution and authoritative zone management.

---

## 🚀 Key architectural features

*   **Hybrid Multiplexing Daemon:** Leverages UNIX `select()` to concurrently monitor and handle synchronous **UDP** datagrams and asynchronous **TCP** streams on port 53.
*   **Concurreny Model:** Spawns isolated process topologies via `fork()` inside the TCP pipeline to manage multi-client state concurrently without blocking the master daemon event loop.
*   **Realistic Delegation Chains:** Authentic emulation of DNS referral patterns.

## ⚙️ Compilation, deployment and test

The deployment pipeline is dual-staged using multi-stage Docker builds to keep production images stripped of compilation overhead.

### 1. Generate the Inverted Zone Tree
Run the local zone initialization script to spawn the distributed path directories and resource records:
```bash
chmod +x makeuri.sh
./makeuri.sh
```

### 2. Build and launch the containers
Compile the binary assets (`serverDNS`, `resolver`) inside the GCC build container stage and spin up the runtime stack:
```bash
docker compose down
docker compose up -d --build

### 3. Test
Access the standalone client shell sandbox to verify network routing and packet data consistency:
```bash
docker exec -it dns-client sh
```
Inside the client container terminal, you can perform targeted verification queries:
```sh
dig @172.28.0.20 ://google.com A
dig @172.28.0.20 www.shop.test A
```
