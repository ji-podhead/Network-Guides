


 | [main](https://ji-podhead.github.io/Network-Guides) | [DNS](https://ji-podhead.github.io/Network-Guides/DNS) |[DHCP](https://ji-podhead.github.io/Network-Guides/DHCP) |[Storage](https://ji-podhead.github.io/Network-Guides/storage) | [Repo](https://github.com/ji-podhead/Network-Guides/) |

---

# Storage

 | [Knowledge Base](https://ji-podhead.github.io/Network-Guides/storage/Knowledge%20Base)| [ZFS & Proxmox](https://ji-podhead.github.io/Network-Guides/storage/zfs&proxmox) | [ISCSI & Proxmox & SCST](https://ji-podhead.github.io/Network-Guides/storage/iscsi) |
 

## High Availability (HA) in Networking

High Availability (HA) refers to systems designed to continue operating without interruption during the failure of one or more components. It ensures that critical services remain available and operational under various conditions, enhancing system reliability and minimizing downtime.

### Components of HA Systems

- **Redundant Hardware**: Duplicate components to ensure that if one fails, another can take over seamlessly.
- **Load Balancing**: Distributes traffic across multiple servers to prevent overload and increase efficiency.
- **Clustering**: Groups servers together so they can share workloads and resources, improving performance and resilience.
- **Failover Mechanisms**: Automatically switch operations to a standby component when a primary component fails.

### Types of HA Solutions
- ***Active-Passive HA***
> In an active-passive setup, one server actively handles requests while the other remains idle until it takes over in case of a failure.

***Active-Active HA***
> Active-active HA involves distributing workload between multiple active servers, increasing capacity and reducing single points of failure.

***N+M Redundancy***
> N+M redundancy involves having N active servers and M standby servers ready to take over in case of failures, providing a higher level of availability.

---


## Distributed Storage 

Distributed storage systems spread data across multiple nodes in a cluster to enhance scalability, reliability, and fault tolerance. This document focuses on Distributed Block Storage, where data is stored in blocks and managed independently.

### Types of Distributed Storage

***Object Storage***

Object storage is designed for storing unstructured data, such as images, videos, and backups. Data is organized into objects, each with metadata, allowing for efficient retrieval and management.

***File Storage***

File storage systems manage data as files within a hierarchical namespace. They are optimized for file-based access patterns but can also support block-level access through protocols like NFS or SMB.

***Block Storage***

Block storage divides data into fixed-size blocks, which are managed independently. Each block can be stored on a separate physical drive, allowing for flexible scaling and high performance.

***Distributed Block Storage*** 

(next section)

---

## Distributed Block Storage
#### Examples
- ***DRBD  (Distributed Replicated Block Device)***: Mirrors blockstorage so multiple nodes can use it safely (slow).
- **Ceph**: A highly scalable, open-source software-defined storage platform that supports object, block, and file storage modes.
- **GlusterFS**: A scalable network filesystem that allows for the creation of large, distributed storage solutions.
- **OpenEBS**: Provides container-native block storage solutions for Kubernetes environments.
- **Amazon S3**: A widely-used object storage service that provides scalable storage for data objects.
- **Google Cloud Storage**: Similar to Amazon S3, offering durable, secure, and scalable object storage.
- **Hadoop HDFS**: Designed for storing very large files across multiple machines, providing high aggregate bandwidth through data parallelism.

[***image from wikipedia  describing DRBD functionality***](https://de.wikipedia.org/wiki/DRBD)

![DRBD](https://upload.wikimedia.org/wikipedia/commons/5/5b/DRBD_concept_overview.png)
---

## Comparison

| Type       | Use Case                                                                                   | Example                          |
|------------|----------------------------------------------------------------------------------------------|----------------------------------|
| Object     | Storing unstructured data, backups, and media content                                      | Amazon S3                        |
| File       | Managing structured data in a hierarchical manner                                         | Network Attached Storage (NAS)   |
| Block      | Providing raw block-level storage for databases, virtual machines, and containers           | SAN (Storage Area Network)        |
| Distributed Block Storage | Scalable, high-performance storage for cloud-native applications and big data analytics | Ceph, GlusterFS, OpenEBS         |

---

## Clustered File System

A clustered file system is a type of file system that is designed to operate across a cluster of computers, allowing them to share storage resources efficiently. These systems are built to handle the challenges of distributed computing environments, offering features such as scalability, high availability, and fault tolerance.

### Key Features

- **Scalability**: Easily expand storage capacity by adding more nodes to the cluster.
- **High Availability**: Ensures that data remains accessible even if individual nodes fail.
- **Fault Tolerance**: Protects against data loss by replicating data across multiple nodes.
- **Consistency**: Maintains data consistency across the cluster, preventing conflicts and inconsistencies.
- **Performance**: Optimizes data access and transfer speeds across the network.

### How It Works

Clustered file systems operate by presenting a unified view of the storage resources available across the cluster. When a file or directory is accessed, the system determines the optimal location for the data based on factors such as load balancing and data replication strategies. This process enables efficient data sharing and collaboration among users and applications running on different nodes.

### Examples

- **GFS (Global File System)**: Developed by Red Hat, GFS is designed for Linux clusters and supports shared access to block devices across multiple nodes.
- **OCFS2 (Oracle Cluster File System)**: A high-performance file system developed by Oracle, OCFS2 is designed for real-time applications and supports clustering across multiple platforms.
- **Ceph FS**: Part of the Ceph storage platform, Ceph FS is a POSIX-compliant file system that provides object, block, and file storage in one unified system.
- **GFS (Global File System)**: Developed by Google, GFS is designed for Linux clusters, supporting shared access to block devices across multiple nodes.


---

## Understanding Distributed Storage and Clustered File Systems

Distributed storage and clustered file systems are two concepts that, while related, serve different purposes in the realm of data management and storage. This section aims to clarify the distinctions and provide examples relevant to both.

### Distributed Storage

> Distributed storage systems distribute data across multiple nodes in a network to achieve scalability, reliability, and fault tolerance. Unlike traditional storage architectures, distributed storage does not rely on a central server; instead, data is replicated across several nodes, ensuring that the system remains operational even if some nodes fail.                            
> ### Characteristics
>
> - **Scalability**: Easy expansion by adding more nodes.
> - **Reliability**: Data redundancy reduces the risk of data loss.
> - **Availability**: Continuous service despite node failures.
> - **Performance**: High throughput and low latency due to parallel processing.
> - **Flexibility**: Supports both file and block-level access, catering to a wide range of applications.

## Clustered File Systems
>
> Clustered file systems allow multiple servers to share a common file system, enabling them to access the same set of files as if they were a single system. This approach enhances data sharing and collaboration among servers in a cluster.
>
> ### Characteristics
>
> - **Shared Access**: Multiple servers can access the same files simultaneously.
> - **Location Independence**: Files appear to be located in a single place, abstracting away the underlying distribution.
> - **Redundancy**: Can provide redundancy through mirroring or striping techniques.
> - **Unified Namespace**: Simplifies data management by providing a single namespace for all storage resources.
> - **Data Replication**: Enhances data protection and availability through automatic replication across nodes.
> - **Load Balancing**: Improves performance by automatically distributing read and write operations across the cluster.


## Bridging the Gap

While distributed storage focuses on the architecture of storing data across multiple nodes, clustered file systems concentrate on how multiple servers interact with a shared file system. Both concepts aim to enhance scalability, reliability, and performance but address different aspects of data management.

- **Distributed Storage** is about the physical distribution of data across a network to ensure scalability and reliability.
- **Clustered File Systems** are about logical file system organization across multiple servers, facilitating shared access and collaboration.

Understanding these distinctions helps in selecting the appropriate technology for specific use cases, whether it's the need for scalable storage or efficient data sharing across a cluster of servers.

---
## NFS 

NFS (Network File System) is a distributed file system protocol that allows a system to share directories and files with others over a network. It enables users to access files on remote systems as if they were local.

***File Sharing Protocol***
- NFS facilitates file sharing by allowing users to access files located on remote servers as if they were local to their own workstation.

***Cross-Platform Compatibility***
- NFS is cross-platform, supporting various operating systems, making it a versatile choice for mixed-environment networks.

***Performance Optimization***
- NFS versions 4.x introduce improvements in performance and scalability, addressing limitations found in earlier versions.

### Operational Modes

***Client and Server Roles***
- In an NFS setup, one system acts as the server hosting the shared files, and other systems act as clients accessing those files.

***Read-Only and Read-Write Access***
- NFS can configure shares to be read-only or read-write, depending on the permissions required for the shared files.

---

## iSCSI 

iSCSI (Internet Small Computer System Interface) is a protocol that allows for the transport of block-level data over IP networks. It enables the creation of storage area networks (SANs) by allowing remote servers to access storage as if it were locally attached.

***Remote Storage Access***
- iSCSI allows for the presentation of remote storage devices to the operating system as if they were locally connected, enabling direct access to storage over the network.

***Compatibility with Existing Infrastructure***
- Since iSCSI operates over standard Ethernet connections, it can leverage existing network infrastructure, reducing the need for specialized hardware.

***Cost-Effective SAN Solutions***
- By using iSCSI, organizations can build SANs without the high cost associated with Fibre Channel technology, making it an attractive option for budget-conscious deployments.

### Operational Modes

***Target and Initiator Roles***
- In an iSCSI setup, devices that provide storage are referred to as targets, while devices that request access to the storage are initiators. Targets and initiators communicate over the network to facilitate data transfer.

***Multipath Support***
- iSCSI supports multipathing, allowing data to be accessed through multiple paths for redundancy and increased reliability.
---
## ZFS 

ZFS (Zettabyte File System) is a combined file system and logical volume manager designed by Sun Microsystems. It stands out for its advanced features such as snapshotting, replication, automatic repair, and data compression.

***Integrated Data Protection***
- ZFS employs robust data protection mechanisms, including checksums for data integrity and RAID-Z for fault tolerance.

***Snapshots and Clones***
- It supports instant snapshots of the file system, facilitating easy backups and version control.

***Compression***
- ZFS integrates built-in compression algorithms to reduce storage space requirements.

***RAID-Z***
- Offers a RAID level specifically designed for ZFS, providing data protection without parity overhead.

---

---
## Gluster FS 
GlusterFS is designed with modularity in mind and supports multiple operational modes:

***Standalone Storage***
- A single server that provides the file system over the network, similar to NFS.

***Distributed Storage***
- Multiple servers store and distribute data among themselves and provide it to clients.

***Replicated Storage***
- Multiple servers mirror data among themselves and provide it to clients.

***Distributed Replicated Storage***
- Multiple servers store and replicate data among themselves, distributing it to clients.

***Striped Storage***
- Multiple servers stripe data to deliver higher performance and disk I/O bandwidth.

***Cloud/HPC Storage***
- Similar to Distributed Replicated Storage.

***NFS-like Standalone Storage Server-2***
- Similar to Standalone Storage, but more than one file system is provided.

***Aggregating Three Storage Servers with Unify***
- Three servers that provide a unified file system via Unify, without redundancy.

---

## Ceph 
Ceph is a sophisticated storage manager designed to handle data across a cluster of machines, offering features such as data redundancy and distributed storage management.

***Storage Manager***
- Ceph serves as a storage manager, facilitating the storage of data across various storage resources like HDDs and SSDs.
- It supports a wide range of storage media, including HDDs, SSDs, magnetic tapes, floppy disks, punched tapes, Hollerith-style punch cards, and magnetic drum memories.

***Clustered Storage Manager***
- Ceph is a clustered storage manager, meaning it operates across multiple interconnected machines, forming a cohesive system.
- This architecture enables enhanced scalability and resilience compared to single-machine setups.

***Distributed Storage Manager***
- Beyond being a clustered manager, Ceph is also a distributed storage manager. This implies that data and the supporting infrastructure are dispersed across numerous machines, avoiding centralization.
- Unlike iSCSI, which presents a single logical disk over the network in a 1:1 ratio, Ceph distributes data across multiple nodes, enhancing fault tolerance and scalability.

***Data Redundancy***
- Ceph incorporates data redundancy by maintaining copies of data in separate locations. This strategy protects against data loss due to hardware failure or other disruptions.
- Ensuring data redundancy is crucial for maintaining data integrity and availability in a distributed storage environment.

---
## DRBD Overview

DRBD (Distributed Replicated Block Device) is a distributed storage system that provides block devices over a network. It is designed to allow multiple hosts to access the same block device simultaneously, with data mirrored across the participating nodes.

> DRBD devices are usually readable and writable from only one node at a time, promoting a Primary/Secondary model. This model is beneficial for database workloads and virtual machine root disks. Ceph, on the other hand, supports concurrent access to the same file system from many hosts, making it suitable for disk-image stores and large-file-sized data.

***Mirroring Across Nodes***
- DRBD mirrors data across nodes, ensuring data consistency and availability even in the event of node failures.

***Network-Based Storage***
- It treats network storage as a local block device, simplifying the management of remote storage.

***Automatic Failover and Recovery***
- DRBD can automatically switch between primary and secondary nodes, minimizing downtime and manual intervention.

### Operational Modes

***Active-Passive Mode***
- Typically, DRBD operates in an active-passive mode, where one node is the primary (active) and others are secondary (passive). This mode is straightforward and ensures data integrity.

***Active-Active Mode***
- With advanced configurations, DRBD can operate in an active-active mode, allowing concurrent access to the same block device from multiple nodes. This mode requires careful synchronization to prevent conflicts.


***Block Devices and Distribution of Storage***
- DRBD provisions block device resources on partitions in a RAID-1 like manner across cluster nodes, ensuring data redundancy. Ceph's RADOS Block Device (RBD) creates storage objects distributed within the RADOS cluster, presenting a highly scalable solution but with computational overhead for determining read/write locations.

