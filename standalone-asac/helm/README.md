# Cisco ASAc Helm Chart

This Helm chart deploys Cisco ASA Container (ASAc) as a standalone firewall on Kubernetes.

## Prerequisites

- Kubernetes cluster with Multus CNI installed
- Hugepages configured on worker nodes (2Mi pages)
- Network interfaces available on worker nodes for management and data traffic

## Deployment Modes

### 1. Standalone Mode (Default)

Single ASAc pod deployment using macvlan networking.

- Single ASAc pod deployment
- Uses day0-config and interface-config

```bash
helm install asac ./helm
```

### 2. High Availability (HA) Mode

Deploys primary and secondary ASAc pods on different nodes.

- Deploys primary and secondary ASAc pods
- Uses day0-config-primary, day0-config-secondary, and interface-config-ha
- Pods scheduled on different nodes via podAntiAffinity
- Adds failover interface (GigabitEthernet0/0 for HA link)

```yaml
# values.yaml
asac:
  enable_ha: "true"
```

```bash
helm install asac ./helm --set asac.enable_ha=true
```

### 3. SR-IOV Mode

For high-performance deployments using SR-IOV virtual functions.

#### SR-IOV Setup Steps

**Step 1:** Copy the SR-IOV deployment template to replace the default deployment:

```bash
cp helm/features/sriov-deployment.yaml helm/templates/deployment.yaml
```

**Step 2:** Update `interface-config` file to use `vfio-pci` driver for data interfaces (net2 and net3):

```ini
[interface0]
  iface_id = net1;
  uio_driver = afpacket;
[interface1]
  iface_id = net2;
  uio_driver = vfio-pci;
[interface2]
  iface_id = net3;
  uio_driver = vfio-pci;
```

> **Note:** Only net2 and net3 (data interfaces) should use `vfio-pci`. The management interface (net1) remains with `afpacket`.

**Step 3:** Update `day0-config` file to use TenGigabitEthernet interfaces instead of GigabitEthernet:

Change:
```
interface GigabitEthernet0/0
interface GigabitEthernet0/1
```

To:
```
interface TenGigabitEthernet0/0
interface TenGigabitEthernet0/1
```

**Step 5:** Update `values.yaml` with your SR-IOV configuration:

```yaml
asac:
  enable_sriov: "true"

worker_nodes:
  # SR-IOV Network Attachment Definition names
  asacData1NetAttDef: "sriov-net-ens7f0"
  asacData2NetAttDef: "sriov-net-ens7f1"
  
  # SR-IOV Physical Function resource names
  sriovPF1: "intel.com/intel_sriov_ens7f0"
  sriovPF2: "intel.com/intel_sriov_ens7f1"
```

**Step 6:** Deploy the chart:

```bash
helm install asac ./helm
```

## Configuration

### Key Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `asac.repository` | Container image repository | `localhost:5000/asac_9.22.2.115` |
| `asac.app_name` | Application name | `asac` |
| `asac.cpus` | Number of CPUs | `2` |
| `asac.memory` | Memory in MB | `4096` |
| `asac.enable_ha` | Enable HA mode | `"false"` |
| `asac.enable_sriov` | Enable SR-IOV mode | `"false"` |

### Network Interfaces

| Parameter | Description | Default |
|-----------|-------------|---------|
| `worker_nodes.asacMgmtInterface` | Management interface | `ens224` |
| `worker_nodes.asacData1Interface` | Data interface 1 (inside) | `ens256` |
| `worker_nodes.asacData2Interface` | Data interface 2 (outside) | `ens161` |
| `worker_nodes.asacFoverInterface` | Failover interface (HA) | `ens193` |

## Uninstalling

```bash
helm uninstall asac
```

## License

Copyright (c) 2024 Cisco Systems Inc or its affiliates. Licensed under the Apache License, Version 2.0.
