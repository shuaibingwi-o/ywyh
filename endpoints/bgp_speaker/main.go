package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func main() {
	var sock string
	var sid string
	var local string
	var remote string
	var nonInteractive bool

	flag.StringVar(&sock, "socket", "/tmp/pce_bgp.sock", "Unix socket path to send raw BGP bytes to")
	flag.StringVar(&sid, "sid", "", "SRv6 SID to advertise (e.g. 2001:db8::200)")
	flag.StringVar(&local, "local", "1.1.1.1", "Local router ID")
	flag.StringVar(&remote, "remote", "2.2.2.2", "Remote router ID")
	flag.BoolVar(&nonInteractive, "non-interactive", false, "Run without interactive prompts (requires --sid)")
	// suppress automatic usage output; only show usage on explicit errors
	flag.Usage = func() {}
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	if !nonInteractive {
		// interactive prompts
		fmt.Print("Unix socket path (/tmp/pce_bgp.sock): ")
		s, _ := reader.ReadString('\n')
		s = strings.TrimSpace(s)
		if s != "" {
			sock = s
		}

		fmt.Print("SRv6 SID to advertise (e.g. 2001:db8::200): ")
		sidRaw, _ := reader.ReadString('\n')
		ss := strings.TrimSpace(sidRaw)
		if ss != "" {
			sid = ss
		}

		fmt.Print("Local router ID (e.g. 1.1.1.1): ")
		localRaw, _ := reader.ReadString('\n')
		if l := strings.TrimSpace(localRaw); l != "" {
			local = l
		}

		fmt.Print("Remote router ID (e.g. 2.2.2.2): ")
		remoteRaw, _ := reader.ReadString('\n')
		if r := strings.TrimSpace(remoteRaw); r != "" {
			remote = r
		}
	}

	if sid == "" {
		fmt.Fprintln(os.Stderr, "Error: SRv6 SID must be provided via --sid or interactively")
		printUsage()
		os.Exit(1)
	}

	fmt.Printf("About to send BGP-LS update to %s with SID=%s, local=%s, remote=%s\n", sock, sid, local, remote)

	msg := constructBGPLSUpdate(sid, local, remote)
	data, err := msg.Serialize()
	if err != nil {
		fmt.Printf("Failed to serialize BGP message: %v\n", err)
		os.Exit(1)
	}

	c, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Printf("Failed to connect to unix socket %s: %v\n", sock, err)
		os.Exit(1)
	}
	defer c.Close()

	_, err = c.Write(data)
	if err != nil {
		fmt.Printf("Failed to write to unix socket: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sent BGP-LS update (%d bytes) to %s\n", len(data), sock)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [--socket path] [--sid SID] [--local RID] [--remote RID] [--non-interactive]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "If --non-interactive is not set, the program will prompt for values.")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  ", os.Args[0], "--sid 2001:db8::200 --non-interactive")
}

func constructBGPLSUpdate(srv6SID, localRID, remoteRID string) *bgp.BGPMessage {
	localDesc := &bgp.LsNodeDescriptor{
		Asn:         65000,
		BGPRouterID: netip.MustParseAddr(localRID),
	}
	remoteDesc := &bgp.LsNodeDescriptor{
		Asn:         65000,
		BGPRouterID: netip.MustParseAddr(remoteRID),
	}
	localNodeTLV := bgp.NewLsTLVNodeDescriptor(localDesc, bgp.LS_TLV_LOCAL_NODE_DESC)
	remoteNodeTLV := bgp.NewLsTLVNodeDescriptor(remoteDesc, bgp.LS_TLV_REMOTE_NODE_DESC)
	linkNLRI := &bgp.LsLinkNLRI{
		LocalNodeDesc:  &localNodeTLV,
		RemoteNodeDesc: &remoteNodeTLV,
		LinkDesc:       []bgp.LsTLVInterface{},
	}

	// Build SRv6 End.X SID TLV using constructor to ensure Length is set
	lsSrv6 := &bgp.LsSrv6EndXSID{
		EndpointBehavior: 0x11,
		Flags:            0,
		Algorithm:        0,
		Weight:           0,
		Reserved:         0,
		SIDs:             []netip.Addr{netip.MustParseAddr(srv6SID)},
	}
	lsSrv6TLV := bgp.NewLsTLVSrv6EndXSID(lsSrv6)
	if lsSrv6TLV != nil {
		linkNLRI.LinkDesc = append(linkNLRI.LinkDesc, lsSrv6TLV)
	}
	lsAddrPrefix := &bgp.LsAddrPrefix{
		Type: bgp.LS_NLRI_TYPE_LINK,
		NLRI: linkNLRI,
	}

	// Use MP_REACH_NLRI attribute for BGP-LS NLRI to ensure parser compatibility.
	mpAttrs := []bgp.PathNLRI{{NLRI: lsAddrPrefix}}
	// Use RF_LS family and set next-hop to local router ID
	attr, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_LS, mpAttrs, netip.MustParseAddr(localRID))
	return bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{attr}, nil)
}
