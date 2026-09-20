package main

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// History is kept at two resolutions so the whole thing stays in a few MB:
// per-minute detail for a day, per-hour for a quarter. That covers both
// "what is happening right now" and "was this box already bad in July".
const (
	minuteSlots = 1440 // 24h
	hourSlots   = 2160 // 90d
	maxNames    = 16   // per host, by frequency
)

type ring struct {
	Counts []uint32 `json:"c"`
	Epochs []int64  `json:"e"` // absolute minute/hour each slot holds
}

func newRing(n int) *ring {
	return &ring{Counts: make([]uint32, n), Epochs: make([]int64, n)}
}

func (r *ring) add(epoch int64, n uint32) {
	i := int(epoch) % len(r.Counts)
	if i < 0 {
		i += len(r.Counts)
	}
	if r.Epochs[i] != epoch {
		r.Epochs[i] = epoch
		r.Counts[i] = 0
	}
	r.Counts[i] += n
}

func (r *ring) at(epoch int64) uint32 {
	i := int(epoch) % len(r.Counts)
	if i < 0 {
		i += len(r.Counts)
	}
	if r.Epochs[i] != epoch {
		return 0
	}
	return r.Counts[i]
}

// series returns the last n buckets ending at epoch, oldest first.
func (r *ring) series(epoch int64, n int) []uint32 {
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = r.at(epoch - int64(n-1-i))
	}
	return out
}

func (r *ring) sum(epoch int64, n int) uint64 {
	var t uint64
	for i := 0; i < n; i++ {
		t += uint64(r.at(epoch - int64(i)))
	}
	return t
}

// Host is one talker: an IP where we have one, otherwise a MAC.
type Host struct {
	Key       string            `json:"key"`
	MAC       string            `json:"mac"`
	Hostname  string            `json:"hostname,omitempty"`
	Protos    map[string]uint64 `json:"protos"`
	Names     map[string]uint64 `json:"names"`
	Total     uint64            `json:"total"`
	Bytes     uint64            `json:"bytes"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
	Minutes   *ring             `json:"minutes"`
	Hours     *ring             `json:"hours"`

	lastAlert time.Time
}

func newHost(key, mac string, now time.Time) *Host {
	return &Host{
		Key: key, MAC: mac,
		Protos:    map[string]uint64{},
		Names:     map[string]uint64{},
		FirstSeen: now, LastSeen: now,
		Minutes: newRing(minuteSlots),
		Hours:   newRing(hourSlots),
	}
}

// TopProto is the protocol this host talks most.
func (h *Host) TopProto() string {
	best, n := "", uint64(0)
	for p, c := range h.Protos {
		if c > n {
			best, n = p, c
		}
	}
	return best
}

// TopName is the service name it repeats most, the best identifying clue.
func (h *Host) TopName() (string, uint64) {
	best, n := "", uint64(0)
	for s, c := range h.Names {
		if c > n {
			best, n = s, c
		}
	}
	return best, n
}

func (h *Host) trimNames() {
	if len(h.Names) <= maxNames*2 {
		return
	}
	type kv struct {
		k string
		v uint64
	}
	all := make([]kv, 0, len(h.Names))
	for k, v := range h.Names {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	kept := map[string]uint64{}
	for _, e := range all[:maxNames] {
		kept[e.k] = e.v
	}
	h.Names = kept
}

// Store owns all state. One mutex is plenty at these packet rates.
type Store struct {
	mu    sync.RWMutex
	Hosts map[string]*Host `json:"hosts"`
	Start time.Time        `json:"start"`
}

func NewStore() *Store {
	return &Store{Hosts: map[string]*Host{}, Start: time.Now()}
}

func minuteOf(t time.Time) int64 { return t.Unix() / 60 }
func hourOf(t time.Time) int64   { return t.Unix() / 3600 }

func (s *Store) Add(p *Packet, now time.Time) {
	key := p.SrcIP
	if key == "" {
		key = p.SrcMAC
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	h, ok := s.Hosts[key]
	if !ok {
		h = newHost(key, p.SrcMAC, now)
		s.Hosts[key] = h
	}
	h.LastSeen = now
	h.Total++
	h.Bytes += uint64(p.Bytes)
	h.Protos[p.Proto]++
	if p.Name != "" {
		h.Names[p.Name]++
		h.trimNames()
	}
	h.Minutes.add(minuteOf(now), 1)
	h.Hours.add(hourOf(now), 1)
}

// Row is a flattened host for the dashboard and the JSON API.
type Row struct {
	Key       string   `json:"key"`
	MAC       string   `json:"mac"`
	Hostname  string   `json:"hostname,omitempty"`
	PPSNow    float64  `json:"pps_now"`
	PPSHour   float64  `json:"pps_hour"`
	Day       uint64   `json:"packets_24h"`
	Total     uint64   `json:"packets_total"`
	Proto     string   `json:"top_proto"`
	Name      string   `json:"top_name"`
	NameCount uint64   `json:"top_name_count"`
	Spark     []uint32 `json:"spark"`
	Status    string   `json:"status"`
	LastSeen  string   `json:"last_seen"`
}

// Rows renders current state, sorted by recent rate, worst first.
func (s *Store) Rows(now time.Time, warn, crit float64) []Row {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, hr := minuteOf(now), hourOf(now)
	out := make([]Row, 0, len(s.Hosts))
	for _, h := range s.Hosts {
		// The current minute is partial, so rate off the previous one.
		ppsNow := float64(h.Minutes.at(m-1)) / 60.0
		ppsHour := float64(h.Minutes.sum(m, 60)) / 3600.0
		name, nc := h.TopName()

		status := "ok"
		switch {
		case ppsNow >= crit:
			status = "crit"
		case ppsNow >= warn:
			status = "warn"
		}

		out = append(out, Row{
			Key: h.Key, MAC: h.MAC, Hostname: h.Hostname,
			PPSNow: ppsNow, PPSHour: ppsHour,
			Day:   h.Minutes.sum(m, minuteSlots),
			Total: h.Total,
			Proto: h.TopProto(), Name: name, NameCount: nc,
			Spark:    h.Minutes.series(m, 60),
			Status:   status,
			LastSeen: now.Sub(h.LastSeen).Truncate(time.Second).String(),
		})
		_ = hr
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PPSNow != out[j].PPSNow {
			return out[i].PPSNow > out[j].PPSNow
		}
		return out[i].Day > out[j].Day
	})
	return out
}

// Totals for the header line.
func (s *Store) Totals(now time.Time) (hosts int, ppm uint64, allTime uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := minuteOf(now)
	for _, h := range s.Hosts {
		hosts++
		ppm += uint64(h.Minutes.at(m - 1))
		allTime += h.Total
	}
	return
}

// Offenders returns hosts over threshold that haven't alerted within cooldown,
// marking them alerted. Called once a minute.
func (s *Store) Offenders(now time.Time, threshold float64, cooldown time.Duration) []Row {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := minuteOf(now)
	var out []Row
	for _, h := range s.Hosts {
		pps := float64(h.Minutes.at(m-1)) / 60.0
		if pps < threshold {
			continue
		}
		if now.Sub(h.lastAlert) < cooldown {
			continue
		}
		h.lastAlert = now
		name, nc := h.TopName()
		out = append(out, Row{
			Key: h.Key, MAC: h.MAC, Hostname: h.Hostname,
			PPSNow: pps, Proto: h.TopProto(), Name: name, NameCount: nc,
			Day: h.Minutes.sum(m, minuteSlots), Total: h.Total,
		})
	}
	return out
}

// SetHostname records a resolved name.
func (s *Store) SetHostname(key, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.Hosts[key]; ok {
		h.Hostname = name
	}
}

// UnresolvedKeys lists IP hosts with no hostname yet.
func (s *Store) UnresolvedKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for k, h := range s.Hosts {
		if h.Hostname == "" && h.MAC != k {
			out = append(out, k)
		}
	}
	return out
}

// Save writes a gzipped JSON snapshot, atomically.
func (s *Store) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(f)

	s.mu.RLock()
	err = json.NewEncoder(zw).Encode(s)
	s.mu.RUnlock()

	if err != nil {
		zw.Close()
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Load restores a snapshot. A missing file is not an error.
func (s *Store) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer zr.Close()

	var loaded Store
	if err := json.NewDecoder(zr).Decode(&loaded); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, h := range loaded.Hosts {
		if h.Minutes == nil || len(h.Minutes.Counts) != minuteSlots {
			h.Minutes = newRing(minuteSlots)
		}
		if h.Hours == nil || len(h.Hours.Counts) != hourSlots {
			h.Hours = newRing(hourSlots)
		}
		if h.Protos == nil {
			h.Protos = map[string]uint64{}
		}
		if h.Names == nil {
			h.Names = map[string]uint64{}
		}
		s.Hosts[k] = h
	}
	if !loaded.Start.IsZero() {
		s.Start = loaded.Start
	}
	return nil
}
