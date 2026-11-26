# User guide — Networks & IPAM

Document subnets, VLANs, gateways and DNS servers, and manage the IP addresses inside them.

## Add a network

1. Select **Add record** and choose the organization.
2. Enter the IPv4 subnet in CIDR form, for example `10.0.0.0/24`.
3. Optionally add the VLAN ID, gateway, DNS servers, location and purpose.
4. Select **Create record**.

## Allocate addresses

Open a network to see its **IP allocations**, then select **Allocate IP address** to add one in that subnet.

## Validation

- Subnets must be valid IPv4 CIDR ranges, and the gateway must sit inside the subnet.
- You cannot change a subnet in a way that would leave existing allocations outside it.
