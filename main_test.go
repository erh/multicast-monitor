package main

import (
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// buildMDNS assembles a real-shaped IPv4/UDP/mDNS frame.
func buildMDNS(srcIP [4]byte, name string, query bool) []byte {
	// DNS payload: header + one question.
	var dns []byte
	hdr := make([]byte, 12)
	if !query {
		binary.BigEndian.PutUint16(hdr[2:4], 0x8400) // response + AA
		binary.BigEndian.PutUint16(hdr[6:8], 1)      // ANCOUNT
	} else {
		binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT
	}
	dns = append(dns, hdr...)
	for _, label := range splitDots(name) {
		dns = append(dns, byte(len(label)))
		dns = append(dns, label...)
	}
	dns = append(dns, 0x00, 0x00, 0x0c, 0x00, 0x01) // root + QTYPE/QCLASS

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 5353)
	binary.BigEndian.PutUint16(udp[2:4], 5353)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(dns)))
	udp = append(udp, dns...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udp)))
	ip[9] = 17 // UDP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], []byte{224, 0, 0, 251})
	ip = append(ip, udp...)

	eth := []byte{
		0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, // dst multicast
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
		0x08, 0x00,
	}
	return append(eth, ip...)
}

func splitDots(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestDecodeMDNSQuery(t *testing.T) {
	f := buildMDNS([4]byte{10, 1, 2, 30}, "_companion-link._tcp.local", true)
	p := decode(f)
	if p == nil {
		t.Fatal("decode returned nil")
	}
	if p.Proto != "mdns" {
		t.Errorf("proto = %q, want mdns", p.Proto)
	}
	if p.SrcIP != "10.1.2.30" {
		t.Errorf("src = %q, want 10.1.2.30", p.SrcIP)
	}
	if p.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %q", p.SrcMAC)
	}
	if p.Name != "_companion-link._tcp.local" {
		t.Errorf("name = %q", p.Name)
	}
	if !p.IsQuery {
		t.Error("expected a query")
	}
}

func TestDecodeMDNSResponse(t *testing.T) {
	f := buildMDNS([4]byte{10, 1, 2, 44}, "Brother-HL._ipp._tcp.local", false)
	p := decode(f)
	if p == nil {
		t.Fatal("decode returned nil")
	}
	if p.IsQuery {
		t.Error("expected a response")
	}
	if p.Name != "Brother-HL._ipp._tcp.local" {
		t.Errorf("name = %q", p.Name)
	}
}

func TestDecodeARP(t *testing.T) {
	f := make([]byte, 42)
	copy(f[6:12], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	binary.BigEndian.PutUint16(f[12:14], 0x0806)
	binary.BigEndian.PutUint16(f[14:16], 1) // Ethernet hardware type
	copy(f[28:32], []byte{10, 1, 2, 7})
	p := decode(f)
	if p == nil || p.Proto != "arp" {
		t.Fatalf("got %+v, want arp", p)
	}
	if p.SrcIP != "10.1.2.7" {
		t.Errorf("src = %q, want 10.1.2.7", p.SrcIP)
	}
}

func TestDecodeGarbage(t *testing.T) {
	for _, f := range [][]byte{
		{},
		{0x01, 0x02},
		make([]byte, 20), // ethertype 0, too short
	} {
		if p := decode(f); p != nil && p.Proto != "" && p.Proto != "arp" {
			t.Errorf("decode(%v) = %+v, want nil or empty", f, p)
		}
	}
}

func TestReadDNSNameTruncated(t *testing.T) {
	// Length byte claims 40 bytes but only 3 follow.
	b := append(make([]byte, 12), 40, 'a', 'b', 'c')
	if got := readDNSName(b, 12); got != "" {
		t.Errorf("got %q, want empty on truncation", got)
	}
}

func TestReadDNSNameLoop(t *testing.T) {
	// A compression pointer aimed at itself must not hang.
	b := make([]byte, 16)
	b[12] = 0xc0
	b[13] = 12
	done := make(chan string, 1)
	go func() { done <- readDNSName(b, 12) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readDNSName hung on a self-referential pointer")
	}
}

func TestRingRollover(t *testing.T) {
	r := newRing(10)
	r.add(5, 3)
	if got := r.at(5); got != 3 {
		t.Errorf("at(5) = %d, want 3", got)
	}
	// Same slot index, later epoch: must reset rather than accumulate.
	r.add(15, 4)
	if got := r.at(15); got != 4 {
		t.Errorf("at(15) = %d, want 4", got)
	}
	if got := r.at(5); got != 0 {
		t.Errorf("at(5) = %d after rollover, want 0", got)
	}
}

func TestRingSeriesAndSum(t *testing.T) {
	r := newRing(60)
	for i := int64(0); i < 5; i++ {
		r.add(100+i, uint32(i+1))
	}
	s := r.series(104, 5)
	want := []uint32{1, 2, 3, 4, 5}
	for i := range want {
		if s[i] != want[i] {
			t.Fatalf("series = %v, want %v", s, want)
		}
	}
	if got := r.sum(104, 5); got != 15 {
		t.Errorf("sum = %d, want 15", got)
	}
}

func TestStoreAddAndRows(t *testing.T) {
	s := NewStore()
	now := time.Now()
	prev := now.Add(-time.Minute)

	for i := 0; i < 180; i++ { // 3 pkt/s for a minute
		s.Add(&Packet{SrcIP: "10.1.2.30", SrcMAC: "aa:bb:cc:dd:ee:ff",
			Proto: "mdns", Name: "_companion-link._tcp.local", Bytes: 100}, prev)
	}
	s.Add(&Packet{SrcIP: "10.1.2.44", SrcMAC: "11:22:33:44:55:66",
		Proto: "ssdp", Bytes: 300}, prev)

	rows := s.Rows(now, 0.5, 2.0)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Key != "10.1.2.30" {
		t.Errorf("worst offender = %q, want 10.1.2.30", rows[0].Key)
	}
	if rows[0].Status != "crit" {
		t.Errorf("status = %q, want crit at 3 pkt/s", rows[0].Status)
	}
	if rows[0].PPSNow < 2.9 || rows[0].PPSNow > 3.1 {
		t.Errorf("pps = %f, want ~3", rows[0].PPSNow)
	}
	if rows[0].Name != "_companion-link._tcp.local" {
		t.Errorf("name = %q", rows[0].Name)
	}
	if rows[1].Status != "ok" {
		t.Errorf("quiet host status = %q, want ok", rows[1].Status)
	}
}

func TestOffendersCooldown(t *testing.T) {
	s := NewStore()
	now := time.Now()
	for i := 0; i < 300; i++ {
		s.Add(&Packet{SrcIP: "10.1.2.30", Proto: "mdns"}, now.Add(-time.Minute))
	}
	if got := s.Offenders(now, 2.0, time.Hour); len(got) != 1 {
		t.Fatalf("first check returned %d offenders, want 1", len(got))
	}
	if got := s.Offenders(now, 2.0, time.Hour); len(got) != 0 {
		t.Errorf("second check returned %d, want 0 (cooldown)", len(got))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/state.json.gz"

	s := NewStore()
	now := time.Now()
	for i := 0; i < 50; i++ {
		s.Add(&Packet{SrcIP: "10.1.2.30", SrcMAC: "aa:bb:cc:dd:ee:ff",
			Proto: "mdns", Name: "_airplay._tcp.local", Bytes: 120}, now)
	}
	if err := s.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	s2 := NewStore()
	if err := s2.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	h, ok := s2.Hosts["10.1.2.30"]
	if !ok {
		t.Fatal("host missing after reload")
	}
	if h.Total != 50 {
		t.Errorf("total = %d, want 50", h.Total)
	}
	if h.Names["_airplay._tcp.local"] != 50 {
		t.Errorf("name count = %d, want 50", h.Names["_airplay._tcp.local"])
	}
	if h.Minutes.at(minuteOf(now)) != 50 {
		t.Errorf("minute bucket = %d, want 50", h.Minutes.at(minuteOf(now)))
	}
}

func TestLoadMissingFileIsFine(t *testing.T) {
	s := NewStore()
	if err := s.Load(t.TempDir() + "/nope.json.gz"); err != nil {
		t.Errorf("missing file should not error, got %v", err)
	}
}

func TestTrimNames(t *testing.T) {
	h := newHost("10.0.0.1", "aa:bb:cc:dd:ee:ff", time.Now())
	for i := 0; i < 100; i++ {
		h.Names[string(rune('a'+i%26))+"._tcp.local"] = uint64(i)
		h.trimNames()
	}
	if len(h.Names) > maxNames*2 {
		t.Errorf("names grew to %d, want <= %d", len(h.Names), maxNames*2)
	}
}

func TestCommas(t *testing.T) {
	cases := map[uint64]string{0: "0", 999: "999", 1000: "1,000",
		1234567: "1,234,567", 10000: "10,000"}
	for in, want := range cases {
		if got := commas(in); got != want {
			t.Errorf("commas(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestDashboardRenders(t *testing.T) {
	s := NewStore()
	now := time.Now()
	for i := 0; i < 400; i++ {
		s.Add(&Packet{SrcIP: "10.1.2.30", SrcMAC: "aa:bb:cc:dd:ee:ff",
			Proto: "mdns", Name: "_companion-link._tcp.local", Bytes: 110},
			now.Add(-time.Duration(i%50+60)*time.Second))
	}
	s.SetHostname("10.1.2.30", "conf-appletv.lan")
	for i := 0; i < 12; i++ {
		s.Add(&Packet{SrcIP: "10.1.2.44", SrcMAC: "11:22:33:44:55:66",
			Proto: "ssdp", Bytes: 300}, now.Add(-70*time.Second))
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	routes(s).ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"10.1.2.30", "conf-appletv.lan",
		"_companion-link._tcp", "<svg", "polyline", "crit"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	os.WriteFile("/tmp/dash.html", w.Body.Bytes(), 0o644)
}

func TestAPIHosts(t *testing.T) {
	s := NewStore()
	s.Add(&Packet{SrcIP: "10.1.2.30", Proto: "mdns"}, time.Now().Add(-time.Minute))

	w := httptest.NewRecorder()
	routes(s).ServeHTTP(w, httptest.NewRequest("GET", "/api/hosts", nil))
	var rows []Row
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(rows) != 1 || rows[0].Key != "10.1.2.30" {
		t.Errorf("rows = %+v", rows)
	}
}
