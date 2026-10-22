---
type: cert
cert: CPTS
module: "Footprinting"
number: 4
status: not-started
tags: [cert, cpts]
---

# Footprinting

Module 4 of 28. Back to [[CPTS/CPTS Index|CPTS Index]].

## Key Concepts
-

## Notes

### Principles of Enumeration
1. There is more than meets the eye. Consider all POVs
2. Distinguish between what we see and what we do not see.
3. There are always ways to gain more information.

### Enumeration Process
3 levels to it:
1. Infrastructure-based 
2. Host-based
3. OS-based

Layers of Enumeration:
1. Internet Presence
	1. identify all possible target systems and interfaces that can be tested
		1. domains, subdomains, vhosts, ASN, netblocks, IP addresses, cloud instances, security measures
2. Gateway
	1. understand what we are dealing with and what we gotta watch out for
		1. firewalls, dmz, ips/ids, edr, proxies, nac, network segmentation, vpn, cloudflare
3. Accessible Services
	1. understand the reason/functionality of target system and gain the necessary knowledge to communicate with it and EXPLOIT it for our purposes effectively
		1. service type, functionality, configuration, port, version, interface
4. Processes
	1. to understand these factors and identify the dependencies between them 
		1. PID, process data, tasks, source, destination
5. Privileges
	1. identify these and understand the  possibilities/limits of these privileges
		1. GROUPS, users, permissions, restrictions, environment
6. OS Setup
	1. see how admins manage the system and what sensitive internal information we can glean from them
		1. os type, patch level, network config, etc.

### Domain Information 
## Commands
```bash

```
