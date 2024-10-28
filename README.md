# Flow

Flow enables [BGP Flow Specification (flowspec)](https://www.rfc-editor.org/rfc/rfc8955.html) on Linux software routers/firewalls. It acts as a sink that receives routes from another BGP speaker and transforms flowspecs into [nftables](https://wiki.nftables.org) rules.

It:

- executes BGP flowspec on Linux, using nftables;
- enables what previously can only be done on commercial routers or [bulky routing software](https://frrouting.org) on lightweight Linux systems.

It doesn't:

- work as a full-blown BGP client; you will need another BGP implementation (likely running on the same node) like [BIRD](https://bird.network.cz) or [OpenBGPD](https://www.openbgpd.org) to peer with others;
- allow multiple BGP sessions, only one-on-one;
- initiate BGP session actively;
- currently support VRF and VPN routes.
