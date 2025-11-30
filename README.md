# XDP-Based Real-Time DDoS Defense System (Dockerized)

This system provides real-time detection and mitigation of DDoS attacks using flow-based machine learning and kernel-level packet enforcement.

It consists of:

- NFStream for real-time feature extraction
- AdaBoost machine learning model for traffic classification
- Redis for attack signaling
- XDP/eBPF for kernel-level enforcement
- Elasticsearch and Kibana for logging and visualization

All components run inside Docker containers orchestrated with Docker Compose.

---

## Hardware Requirements

Recommended minimum specifications:

- 64-bit Linux host  
- 4 CPU cores (2 minimum)  
- 8 GB RAM (4 minimum)  
- 20 GB free disk space  
- XDP-capable network interface  
- Root or sudo privileges (required for XDP attachment)

---

## Software Requirements

This system was tested and verified on:

- **Ubuntu 22.04.05 LTS**
- **Kernel version: 5.15.0-161-generic**

If system requirements are met (Docker support, kernel compatibility, privileges, and NIC capability), the system should run successfully on any modern Linux distribution.

### Check Kernel Version

```bash
uname -r
```

---

## Docker Environment

This system was verified using:

* Docker Engine: **29.1.1**
* Docker Compose: **v2.40.3**

Verify locally:

```bash
docker compose version
docker --version
```

---

## Virtual Machine Note

If running inside a virtual machine (VMware / VirtualBox / KVM):

Use **Bridged Mode** in the network interface configurations

Using NAT mode is not optimal as it:

* Hides real source IPs
* Breaks proper packet capture
* Prevents XDP attachment
* Causes incorrect enforcement behavior

---

## Installation and Startup

1. Clone or download the repository:

```bash
git clone https://github.com/rexsez/ddos-defense.git
```

Or download manually from: https://github.com/rexsez/ddos-defense.git

2. Navigate into the project:

```bash
cd ddos-defense
```

3. Make scripts executable:

```bash
chmod +x start.sh manage_blacklist.sh
```

4. Start the system:

```bash
sudo ./start.sh
```

---

## NIC Auto-Detection

`start.sh` automatically detects the active network interface and assigns it for:

* XDP attachment
* NFStream capture

Example console output:

```
Detecting network interface...
Using interface: ens33
```

In most cases, no configuration is needed.

If traffic is missing or enforcement is not working, update the interface inside `.env`.

---

## Expected Startup Output

After running `./start.sh`, you should see:

```
Detecting network interface...
Using interface: ens33

Container ddos-elasticsearch  Healthy
Container ddos-redis          Healthy
Container ddos-kibana         Started
Container ddos-app            Started
```

Service Info:

```
Network Interface: ens33

Access:
Kibana:        http://localhost:5601
Elasticsearch: http://localhost:9200
Redis:         localhost:6379

Credentials:
Username: elastic
Password: jgYsL5-kztDUSd8HyiNd
```

Only ensure:

✅ NIC printed  
✅ Elasticsearch healthy  
✅ ddos-app running  
✅ URLs shown

---

## Service Verification

Check logs:

```bash
docker logs -f ddos-app
```

Expected output:

```
kibana_system password configured

Created enforcement-blocks template
Created xdp-drops template
Created netflows template

SUCCESS: Kibana is ready
Dashboards imported successfully
Demo data inserted successfully

xdp-controller entered RUNNING state
ml-pipeline entered RUNNING state
```

---

## Service Roles

### XDP Controller

Handles kernel-level enforcement and IP blocking.

### ML Pipeline

Runs NFStream + AdaBoost classification.

Both must be running for detection and mitigation to work.

---

## Accessing Kibana

Open:

[http://localhost:5601](http://localhost:5601)

Login credentials:

```
Username: elastic
Password: jgYsL5-kztDUSd8HyiNd
```

Once logged in:

* Dashboards auto-load
* Traffic updates live (with auto refresh set on the dashboard)
* Drops & blocks appear immediately

---

## Accessing the Dashboard

After logging into Kibana:

1. Click on the hamburger menu (≡) in the top-left corner
2. Navigate to **Analytics** → **Dashboards**
3. Select **XDP and Network Traffic Summary** from the dashboard list
4. The dashboard will display real-time DDoS detection metrics, blocked IPs, and traffic analysis

![Kibana Dashboards Navigation](images/kibana-dashboards-navigation.png)

Alternatively, you can find the dashboard in the **Recently viewed** section if you've accessed it before.

![XDP and Network Traffic Summary Dashboard List](images/xdp-dashboard-list.png)

The dashboard will load and display comprehensive real-time metrics:

![XDP Dashboard Full View](images/xdp-dashboard-full-view.png)


![XDP Dashboard Detailed Metrics](images/xdp-dashboard-detailed-metrics.png)

The dashboard provides:

* Real-time traffic flow statistics
* XDP drop counters and enforcement blocks
* Machine learning classification results
* Attack detection alerts and patterns

---

## Manual Validation via manage_blacklist.sh

This script validates enforcement in seconds.

### Block an IP

```bash
./manage_blacklist.sh block 192.168.1.100
```

### Unblock an IP

```bash
./manage_blacklist.sh unblock 192.168.1.100
```

### List All Blocked

```bash
./manage_blacklist.sh list
```

---

## Expected Results

### On block:

✅ IP inserted into kernel blacklist  
✅ Packets immediately dropped  
✅ Block appears in Kibana  
✅ Drop counters increase

### On unblock:

✅ Kernel removes IP  
✅ Traffic resumes

---

## Content-Based Filtering

The kernel also performs **payload filtering**.

If incoming packets contain:

```
Test Data
```

They are dropped instantly at XDP level.

---

## Content Filter Test

### On protected system:

```bash
nc -lvnp 8080
```

### From attacker machine:

```bash
nc <target-ip> 8080
```

Then send:

```
Test Data
```

---

## Expected Behavior

✅ Packet is dropped at kernel level  
✅ No response received  
✅ Kibana shows drop event  
✅ Reason indicates content-based filtering

---

## Troubleshooting (In Order)

Only check:

1. `.env` NIC value
2. Docker status
3. Containers:

```bash
docker ps
```

4. Logs:

```bash
docker logs ddos-app
```