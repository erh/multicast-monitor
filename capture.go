package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Kernel-side BPF filter.
//
// Generated with:
//   tcpdump -dd -i eth0 '(udp port 5353 or udp port 1900 or udp port 137 or
//                         udp port 138 or udp port 3702) or arp'
//
// Filtering in the kernel rather than userspace is what keeps this at
// negligible CPU on a busy link: the NIC's other traffic never gets copied.
// The final accept returns the snaplen; headers plus a DNS name is all we read.
// ---------------------------------------------------------------------------

const snapLen = 1500

// Local mirrors of struct sock_filter / sock_fprog. Identical layout to the
// kernel's, and using our own types keeps the table pasteable straight from
// tcpdump -dd without vet complaining about unkeyed fields.
type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

var bpfProgram = []sockFilter{
	{0x28, 0, 0, 0x0000000c},
	{0x15, 0, 10, 0x000086dd},
	{0x30, 0, 0, 0x00000014},
	{0x15, 0, 28, 0x00000011},
	{0x28, 0, 0, 0x00000036},
	{0x15, 25, 0, 0x000014e9},
	{0x15, 24, 0, 0x0000076c},
	{0x15, 23, 0, 0x00000089},
	{0x15, 22, 0, 0x0000008a},
	{0x15, 21, 0, 0x00000e76},
	{0x28, 0, 0, 0x00000038},
	{0x15, 19, 14, 0x000014e9},
	{0x15, 0, 17, 0x00000800},
	{0x30, 0, 0, 0x00000017},
	{0x15, 0, 17, 0x00000011},
	{0x28, 0, 0, 0x00000014},
	{0x45, 15, 0, 0x00001fff},
	{0xb1, 0, 0, 0x0000000e},
	{0x48, 0, 0, 0x0000000e},
	{0x15, 11, 0, 0x000014e9},
	{0x15, 10, 0, 0x0000076c},
	{0x15, 9, 0, 0x00000089},
	{0x15, 8, 0, 0x0000008a},
	{0x15, 7, 0, 0x00000e76},
	{0x48, 0, 0, 0x00000010},
	{0x15, 5, 0, 0x000014e9},
	{0x15, 4, 0, 0x0000076c},
	{0x15, 3, 0, 0x00000089},
	{0x15, 2, 0, 0x0000008a},
	{0x15, 1, 2, 0x00000e76},
	{0x15, 0, 1, 0x00000806},
	{0x6, 0, 0, snapLen},
	{0x6, 0, 0, 0x00000000},
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// The syscall package doesn't expose these (they live in x/sys/unix), and the
// whole point here is a zero-dependency binary, so declare them directly.
const (
	solPacket           = 263 // SOL_PACKET
	packetAddMembership = 1   // PACKET_ADD_MEMBERSHIP
	packetMrPromisc     = 1   // PACKET_MR_PROMISC
)

// packetMreq mirrors struct packet_mreq from linux/if_packet.h.
type packetMreq struct {
	Ifindex int32
	Type    uint16
	Alen    uint16
	Address [8]byte
}

// Capture is a raw AF_PACKET socket with the filter attached.
type Capture struct {
	fd    int
	iface string
	buf   []byte
}

// NewCapture opens the socket, attaches the BPF filter, binds to the
// interface and enables promiscuous mode. Requires CAP_NET_RAW.
func NewCapture(ifaceName string) (*Capture, error) {
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", ifaceName, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW,
		int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket (need root or CAP_NET_RAW): %w", err)
	}

	// Attach the filter before binding, so we never see unfiltered traffic.
	prog := sockFprog{
		Len:    uint16(len(bpfProgram)),
		Filter: &bpfProgram[0],
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&prog)), unsafe.Sizeof(prog), 0); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("attach BPF filter: %w", e)
	}

	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind to %s: %w", ifaceName, err)
	}

	// Promiscuous mode. Multicast would mostly arrive anyway, but this also
	// catches unicast responses and anything on a mirrored port.
	mreq := packetMreq{Ifindex: int32(ifi.Index), Type: packetMrPromisc}
	if _, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(solPacket), uintptr(packetAddMembership),
		uintptr(unsafe.Pointer(&mreq)), unsafe.Sizeof(mreq), 0); e != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("enable promiscuous mode: %w", e)
	}

	return &Capture{fd: fd, iface: ifaceName, buf: make([]byte, snapLen)}, nil
}

func (c *Capture) Close() error { return syscall.Close(c.fd) }

// Packet is one decoded frame, reduced to what we count.
type Packet struct {
	SrcMAC  string
	SrcIP   string // empty for ARP
	Proto   string // mdns | ssdp | netbios | wsd | arp
	Name    string // mDNS question or announced name, when present
	Bytes   int
	IsQuery bool
}

// Next blocks until the next matching frame. The returned Packet is valid
// until the following call.
func (c *Capture) Next() (*Packet, error) {
	for {
		n, _, err := syscall.Recvfrom(c.fd, c.buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return nil, err
		}
		if p := decode(c.buf[:n]); p != nil {
			return p, nil
		}
	}
}

func macString(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// decode pulls source, protocol and (for mDNS) a service name out of a frame.
// Returns nil for anything malformed or unrecognised.
func decode(f []byte) *Packet {
	if len(f) < 14 {
		return nil
	}
	p := &Packet{SrcMAC: macString(f[6:12]), Bytes: len(f)}
	ethType := binary.BigEndian.Uint16(f[12:14])

	var payload []byte
	var sport, dport uint16

	switch ethType {
	case 0x0806: // ARP
		p.Proto = "arp"
		// Sender protocol address sits at offset 14+14 for IPv4-over-Ethernet.
		if len(f) >= 28 && binary.BigEndian.Uint16(f[14:16]) == 1 {
			p.SrcIP = net.IP(f[28:32]).String()
		}
		return p

	case 0x0800: // IPv4
		if len(f) < 34 {
			return nil
		}
		ihl := int(f[14]&0x0f) * 4
		if ihl < 20 || len(f) < 14+ihl+8 || f[14+9] != 17 {
			return nil
		}
		p.SrcIP = net.IP(f[26:30]).String()
		udp := f[14+ihl:]
		sport = binary.BigEndian.Uint16(udp[0:2])
		dport = binary.BigEndian.Uint16(udp[2:4])
		payload = udp[8:]

	case 0x86dd: // IPv6
		if len(f) < 62 || f[14+6] != 17 {
			return nil
		}
		p.SrcIP = net.IP(f[22:38]).String()
		udp := f[54:]
		sport = binary.BigEndian.Uint16(udp[0:2])
		dport = binary.BigEndian.Uint16(udp[2:4])
		payload = udp[8:]

	default:
		return nil
	}

	switch {
	case sport == 5353 || dport == 5353:
		p.Proto = "mdns"
		p.Name, p.IsQuery = parseMDNS(payload)
	case sport == 1900 || dport == 1900:
		p.Proto = "ssdp"
	case sport == 137 || dport == 137 || sport == 138 || dport == 138:
		p.Proto = "netbios"
	case sport == 3702 || dport == 3702:
		p.Proto = "wsd"
	default:
		return nil
	}
	return p
}

// parseMDNS extracts the first question name, or the first answer name when
// the packet is a pure announcement. This is the single most useful field for
// identifying an offender: "_companion-link._tcp.local" at 8 queries a second
// is an Apple device with stuck Continuity state, and it says so out loud.
func parseMDNS(b []byte) (name string, isQuery bool) {
	if len(b) < 12 {
		return "", false
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	qdcount := binary.BigEndian.Uint16(b[4:6])
	ancount := binary.BigEndian.Uint16(b[6:8])
	isQuery = flags&0x8000 == 0

	if qdcount == 0 && ancount == 0 {
		return "", isQuery
	}
	// Questions and answers both begin with a name at offset 12.
	return readDNSName(b, 12), isQuery
}

// readDNSName walks the label sequence at off. Compression pointers are
// followed once; malformed input yields whatever was read so far.
func readDNSName(b []byte, off int) string {
	var sb strings.Builder
	jumped := false
	for i := 0; i < 32; i++ { // label count guard
		if off < 0 || off >= len(b) {
			break
		}
		l := int(b[off])
		if l == 0 {
			break
		}
		if l&0xc0 == 0xc0 { // compression pointer
			if jumped || off+1 >= len(b) {
				break
			}
			off = int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3fff)
			jumped = true
			continue
		}
		if off+1+l > len(b) {
			break
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(b[off+1 : off+1+l])
		off += 1 + l
	}
	s := sb.String()
	if len(s) > 120 {
		s = s[:120]
	}
	return strings.ToValidUTF8(s, "")
}
