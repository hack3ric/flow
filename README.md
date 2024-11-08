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

## Usage

Run Flow with default settings that listens to wildcard with port 179, local AS 65000, router ID 127.0.0.1, and no restriction to the other BGP speaker:

```console
# flow run
```

Allow only local AS (IBGP) and IPv6 loopback incoming IP for peer, and change listening port to 1179:

```console
# flow run -b [::]:1179 -l 65001 -r 65001 -a ::1/128
```

The configuration options can be stored in a file and passed directly to Flow using the `-f` option:

```console
# flow run -f flow.conf
```

```
# flow.conf

# Each line is exactly one argument without `--`, and spaces are preserved as-is.
# Empty lines and lines starting with '#' are ignored.

bind=[::1]:1179
local-as=65001
remote-as=65001

# The prefix length can be omitted if it contains only one IP
allowed-ips=::1
```

Configure the remote BGP speaker so it connects and sends flowspecs to Flow. You may need to enable multihop if they are connecting through loopback. For example in BIRD:

```
flow4 table myflow4;
flow6 table myflow6;

protocol bgp flow {
  local port 1180 as 65001;
  neighbor ::1 port 1179 as 65001;
  multihop;

  flow4 { table myflow4; import none; export all; };
  flow6 { table myflow6; import none; export all; };
}
```

Show information of currently running Flow instance:

```console
# flow show
```

## Future Work

- **Implement [Redirect-to-IP Action](https://datatracker.ietf.org/doc/draft-ietf-idr-flowspec-redirect-ip/) draft**: will bring in iproute2/rtnetlink dependency
- **Programmatic handling**: custom traffic filter actions and route handling (not limited to flowspecs)
- [**Validation procedure**](https://www.rfc-editor.org/rfc/rfc8955.html#name-validation-procedure): currently this can be done from the connecting BGP speaker, but for the sake of completeness and also future programmability it should also be done here
- **VPN routes and VRF redirection**: does not have many knowledge right now, but certainly doable
- **OpenBSD `pf` backend**: provide an alternative to Linux

## License

Flow is licensed under the BSD 2-Clause License. See LICENSE file for detail.
