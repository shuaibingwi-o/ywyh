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
	var tcpAddr string
	var sid string
	var local string
	var remote string
	var nonInteractive bool

	flag.StringVar(&tcpAddr, "tcp", "[::1]:179", "TCP IPv6 address to send BGP-LS bytes to (default: [::1]:179)")
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
		fmt.Print("TCP IPv6 address ([::1]:179): ")
		s, _ := reader.ReadString('\n')
		s = strings.TrimSpace(s)
		if s != "" {
			tcpAddr = s
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

	fmt.Printf("About to send BGP-LS update to %s with SID=%s, local=%s, remote=%s\n", tcpAddr, sid, local, remote)

	msg := constructBGPLSUpdate(sid, local, remote)
	data, err := msg.Serialize()
	if err != nil {
		fmt.Printf("Failed to serialize BGP message: %v\n", err)
		os.Exit(1)
	}

	c, err := net.Dial("tcp", tcpAddr)
	if err != nil {
		fmt.Printf("Failed to connect to TCP socket %s: %v\n", tcpAddr, err)
		os.Exit(1)
	}
	defer c.Close()

	_, err = c.Write(data)
	if err != nil {
		fmt.Printf("Failed to write to TCP socket: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sent BGP-LS update (%d bytes) to %s\n", len(data), tcpAddr)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [--tcp addr] [--sid SID] [--local RID] [--remote RID] [--non-interactive]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "If --non-interactive is not set, the program will prompt for values.")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  ", os.Args[0], "--sid 2001:db8::200 --non-interactive")
}

func constructBGPLSUpdate(srv6SID, localRID, remoteRID string) *bgp.BGPMessage {
	localDesc := &bgp.LsNodeDescriptor{
		Asn:         65000,
		BGPRouterID: netip.MustParseAddr(localRID),
	}
	localNodeTLV := bgp.NewLsTLVNodeDescriptor(localDesc, bgp.LS_TLV_LOCAL_NODE_DESC)
	// For SPF parser compatibility, advertise a Node NLRI with a LocalNodeDescriptor.
	// `ApplyBGPUpdateToLSDB` recognizes node NLRI and will register the node in the LSDB.
	nodeNLRI := &bgp.LsNodeNLRI{
		LocalNodeDesc: &localNodeTLV,
	}
	lsAddrPrefix := &bgp.LsAddrPrefix{
		Type: bgp.LS_NLRI_TYPE_NODE,
		NLRI: nodeNLRI,
	}

	// Place the LS NLRI inside an MP_REACH_NLRI (AFI=LS, SAFI=LS)
	nlris := []bgp.PathNLRI{{NLRI: lsAddrPrefix}}
	nextHop := netip.MustParseAddr(localRID)
	attr, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_LS, nlris, nextHop)
	if err != nil {
		fmt.Printf("failed to construct MP_REACH_NLRI: %v\n", err)
		os.Exit(1)
	}
	return bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{attr}, nil)
}
