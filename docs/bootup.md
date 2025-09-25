# Kubernetes the Hard Way: `bootup.bash` Step-by-Step Guide

This document summarizes the `bootup.bash` automation script for setting up a Kubernetes cluster from scratch. Each step is explained with clear descriptions and flow diagrams to illustrate the process.

---

## Overview

The script automates the following high-level stages:

1. **Base System Preparation**
2. **Certificate Authority & Certificates**
3. **Kubeconfig Generation**
4. **Control Plane Bootstrapping**
5. **Worker Node Bootstrapping**
6. **Network Route Setup**

---

## 1. Base System Preparation

- Installs required dependencies (wget, curl, git, etc.)
- Clones the Kubernetes the Hard Way repository
- Downloads Kubernetes binaries and CNI plugins
- Sets up SSH keys for root access
- Configures `/etc/hosts` for all cluster nodes

**Flow Diagram:**

```
+-------------------+
| Install Packages  |
+--------+----------+
         |
         v
+--------+----------+
| Clone Repository  |
+--------+----------+
         |
         v
+--------+----------+
| Download Binaries |
+--------+----------+
         |
         v
+--------+----------+
| Setup SSH & Hosts |
+-------------------+
```

### Function: install_dependencies

**Step-by-step flow:**

1. Update package lists and install base dependencies (wget, curl, git, etc.).
2. Clone the "Kubernetes the Hard Way" repository.
3. Download Kubernetes binaries and CNI plugins for the system architecture.
4. Extract and organize binaries into client, controller, worker, and CNI plugin folders.
5. Set executable permissions and copy `kubectl` to `/usr/local/bin`.
6. Enable SSH and root login, generate SSH key for root, and copy the public key for distribution.
7. If `machine.txt` exists, update `/etc/hosts` for all nodes and set hostnames accordingly.
8. Print the SSH public key for manual distribution if needed.
9. Complete base installation.

---

## 2. Certificate Authority & Certificates

- Sets up a Root CA
- Generates certificates for all Kubernetes components (admin, nodes, kube-proxy, etc.)
- Distributes certificates to the appropriate nodes

**Flow Diagram:**

```
+-------------------+
|  Root CA Setup    |
+--------+----------+
         |
         v
+--------+----------+
| Generate Certs    |
+--------+----------+
         |
         v
+--------+----------+
| Distribute Certs  |
+-------------------+
```

### Function: certificate_installation

**Step-by-step flow:**

1. On the server node, create a CERT directory and copy `ca.conf`.
2. Generate a Root CA private key (`ca.key`) and self-signed certificate (`ca.crt`).
3. Distribute CA files to all nodes.
4. For each component (admin, nodes, kube-proxy, etc.), generate a private key, create a CSR, and sign it with the CA.
5. Distribute node-specific certificates and keys to each node's `/var/lib/kubelet`.
6. On worker nodes, copy back certain certificates to the server for backup.
7. Print the current hostname for verification.

---

## 3. Kubeconfig Generation

- Creates kubeconfig files for each node and component
- Embeds certificates and sets up authentication
- Distributes kubeconfig files to nodes
- Sets up data encryption config
- Generates front-proxy certificates

**Flow Diagram:**

```
+-------------------+
| Generate Kubeconf |
+--------+----------+
         |
         v
+--------+----------+
| Distribute Files  |
+--------+----------+
         |
         v
+--------+----------+
| Data Encryption   |
+--------+----------+
         |
         v
+--------+----------+
| Front-Proxy Certs |
+-------------------+
```

### Function: kubeconfig_configuration

**Step-by-step flow:**

1. For each node, generate a kubeconfig file embedding the correct certificates and cluster info.
2. For each service (kube-proxy, controller-manager, scheduler, admin), generate a kubeconfig with appropriate credentials and context.
3. List all generated kubeconfig files.
4. On the server, call `data_encryption` and `generate_front_proxy_certificates`.
5. Distribute kubeconfig and encryption config files to all nodes.
6. On worker nodes, copy kubeconfig files back to the server for backup.
7. Print completion message.

### Function: data_encryption

**Step-by-step flow:**

1. Display the encryption config template.
2. Generate a random encryption key.
3. Substitute the key into the template and write the final config.
4. Print completion message.

### Function: generate_front_proxy_certificates

**Step-by-step flow:**

1. Generate a front-proxy CA private key and certificate.
2. Generate a front-proxy client private key and CSR.
3. Sign the client CSR with the front-proxy CA.
4. Copy front-proxy certificates to `/var/lib/kubernetes` on the server and distribute to all nodes.
5. Print completion message.

---

## 4. Control Plane Bootstrapping

- Sets up CNI networking on worker nodes
- Copies binaries and config files to control plane
- Starts etcd, kube-apiserver, kube-controller-manager, kube-scheduler
- Waits for API server to become active
- Applies RBAC and verifies cluster status

**Flow Diagram:**

```
+-------------------+
| Setup CNI         |
+--------+----------+
         |
         v
+--------+----------+
| Copy Binaries     |
+--------+----------+
         |
         v
+--------+----------+
| Start Services    |
+--------+----------+
         |
         v
+--------+----------+
| Verify Cluster    |
+-------------------+
```

### Function: bootstrapping_control_plane

**Step-by-step flow:**

1. On the server, set up CNI networking on all worker nodes (copy and configure CNI config files).
2. Copy etcd and Kubernetes controller binaries to `/usr/local/bin`.
3. Create required directories for etcd and Kubernetes configs.
4. Copy all necessary certificates and configs to `/etc/etcd` and `/var/lib/kubernetes`.
5. Set permissions on keys and certificates.
6. Copy and enable systemd unit files for etcd, kube-apiserver, controller-manager, and scheduler.
7. Start all control plane services and wait for kube-apiserver to become active.
8. Set up kubectl config for the admin user.
9. Apply RBAC and API server-to-kubelet configuration.
10. Verify etcd and Kubernetes component status.

---

## 5. Worker Node Bootstrapping

- Installs worker dependencies (socat, conntrack, etc.)
- Copies CNI plugins and worker binaries
- Configures and starts containerd, kubelet, kube-proxy
- Verifies service status

**Flow Diagram:**

```
+-------------------+
| Install Deps      |
+--------+----------+
         |
         v
+--------+----------+
| Copy Binaries     |
+--------+----------+
         |
         v
+--------+----------+
| Start Services    |
+-------------------+
```

### Function: bootstrapping_worker_node

**Step-by-step flow:**

1. On each worker node, install dependencies (socat, conntrack, etc.).
2. Create directories for CNI plugins and Kubernetes runtime.
3. Copy CNI plugins and worker binaries to their respective locations.
4. Load and configure the `br-netfilter` kernel module and sysctl settings.
5. Copy and configure containerd, kubelet, and kube-proxy configs and systemd units.
6. Start containerd, kubelet, and kube-proxy services.
7. Check and print the status of all services.
8. Print completion message.

---

## 6. Network Route Setup

- Configures network routes on server and worker nodes for pod communication

**Flow Diagram:**

```
+-------------------+
| Setup Routes      |
+-------------------+
```

### Function: setup_network_routes

**Step-by-step flow:**

1. On the server, add routes for each worker node subnet via the node's IP.
2. On each worker node, add routes to other worker subnets via the server IP.
3. Print the routing table for each node and the server for verification.

---

## Usage

The script can be run with the following options:

- `base-bringup` — Prepare base system
- `install-certificates` — Set up CA and certificates
- `install-kubeconfig` — Generate and distribute kubeconfig files
- `server-bringup` — Bootstrap control plane
- `worker-bringup` — Bootstrap worker node
- `setup-network` — Configure network routes

Example:

```bash
./bootup.bash base-bringup
./bootup.bash install-certificates
./bootup.bash install-kubeconfig
./bootup.bash server-bringup
./bootup.bash worker-bringup
./bootup.bash setup-network
```

---

## Summary

This script provides a step-by-step, automated approach to building a Kubernetes cluster "the hard way". Each function is modular, allowing you to run and debug each stage independently. The flow diagrams above illustrate the logical sequence of each major step.
