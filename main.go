package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

// version is overridden at build time via -ldflags "-X main.version=..."
var version = "dev"

var (
	flagIface     = flag.String("i", "", "interface to watch (required)")
	flagListen    = flag.String("listen", ":8088", "dashboard listen address")
	flagState     = flag.String("state", "/var/lib/mcastwatch/state.json.gz", "state snapshot path")
	flagWarn      = flag.Float64("warn", 0.5, "packets/sec per host to mark chatty")
	flagCrit      = flag.Float64("crit", 2.0, "packets/sec per host to mark broken and alert")
	flagAlertCmd  = flag.String("alert-cmd", "", "shell command run on threshold breach")
	flagCooldown  = flag.Duration("alert-cooldown", 30*time.Minute, "minimum gap between alerts per host")
	flagSave      = flag.Duration("save-interval", 5*time.Minute, "how often to snapshot state")
	flagNoResolve = flag.Bool("no-resolve", false, "skip reverse DNS lookups")
	flagVersion   = flag.Bool("version", false, "print version and exit")
)

func main() {
	flag.Parse()
	if *flagVersion {
		fmt.Printf("mcastwatch %s\n", version)
		return
	}
	if *flagIface == "" {
		fmt.Fprintln(os.Stderr, "usage: mcastwatch -i <interface> [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("mcastwatch: ")

	store := NewStore()
	if err := store.Load(*flagState); err != nil {
		log.Printf("could not load state from %s: %v (starting fresh)", *flagState, err)
	} else {
		n, _, _ := store.Totals(time.Now())
		log.Printf("loaded %d known host(s) from %s", n, *flagState)
	}

	cap, err := NewCapture(*flagIface)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer cap.Close()
	log.Printf("watching %s (mdns, ssdp, netbios, wsd, arp)", *flagIface)

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Capture loop.
	go func() {
		for {
			p, err := cap.Next()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("capture error: %v", err)
				time.Sleep(time.Second)
				continue
			}
			store.Add(p, time.Now())
		}
	}()

	go alertLoop(ctx, store)
	go saveLoop(ctx, store)
	if !*flagNoResolve {
		go resolveLoop(ctx, store)
	}

	srv := &http.Server{Addr: *flagListen, Handler: routes(store)}
	go func() {
		log.Printf("dashboard on http://%s/", *flagListen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutCtx)
	if err := store.Save(*flagState); err != nil {
		log.Printf("final save failed: %v", err)
	} else {
		log.Printf("state saved to %s", *flagState)
	}
}

// ----------------------------------------------------------------- background

func saveLoop(ctx context.Context, s *Store) {
	t := time.NewTicker(*flagSave)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Save(*flagState); err != nil {
				log.Printf("save failed: %v", err)
			}
		}
	}
}

// alertLoop checks once a minute, just after the minute boundary so the
// previous minute's bucket is complete.
func alertLoop(ctx context.Context, s *Store) {
	for {
		now := time.Now()
		next := now.Truncate(time.Minute).Add(time.Minute + 2*time.Second)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}

		for _, r := range s.Offenders(time.Now(), *flagCrit, *flagCooldown) {
			who := r.Key
			if r.Hostname != "" {
				who = fmt.Sprintf("%s (%s)", r.Key, r.Hostname)
			}
			detail := r.Proto
			if r.Name != "" {
				detail = fmt.Sprintf("%s %s", r.Proto, r.Name)
			}
			log.Printf("ALERT %s at %.2f pkt/s — %s", who, r.PPSNow, detail)
			runAlertCmd(r)
		}
	}
}

func runAlertCmd(r Row) {
	if *flagAlertCmd == "" {
		return
	}
	cmd := exec.Command("/bin/sh", "-c", *flagAlertCmd)
	cmd.Env = append(os.Environ(),
		"MW_HOST="+r.Key,
		"MW_MAC="+r.MAC,
		"MW_HOSTNAME="+r.Hostname,
		fmt.Sprintf("MW_PPS=%.2f", r.PPSNow),
		"MW_PROTO="+r.Proto,
		"MW_NAME="+r.Name,
		fmt.Sprintf("MW_PACKETS_24H=%d", r.Day),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("alert-cmd failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
}

func resolveLoop(ctx context.Context, s *Store) {
	res := &net.Resolver{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		for _, k := range s.UnresolvedKeys() {
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			names, err := res.LookupAddr(c, k)
			cancel()
			if err == nil && len(names) > 0 {
				s.SetHostname(k, strings.TrimSuffix(names[0], "."))
			} else {
				s.SetHostname(k, "-") // don't retry forever
			}
		}
	}
}

// ----------------------------------------------------------------------- http

func routes(s *Store) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Rows(time.Now(), *flagWarn, *flagCrit))
	})

	mux.HandleFunc("/api/host", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		s.mu.RLock()
		h, ok := s.Hosts[key]
		s.mu.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		s.mu.RLock()
		defer s.mu.RUnlock()
		json.NewEncoder(w).Encode(h)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		now := time.Now()
		rows := s.Rows(now, *flagWarn, *flagCrit)
		hosts, ppm, allTime := s.Totals(now)

		data := struct {
			Rows    []Row
			Hosts   int
			PPM     uint64
			AllTime uint64
			Iface   string
			Warn    float64
			Crit    float64
			Since   string
			Now     string
			Version string
		}{
			Rows: rows, Hosts: hosts, PPM: ppm, AllTime: allTime,
			Iface: *flagIface, Warn: *flagWarn, Crit: *flagCrit,
			Since:   now.Sub(s.Start).Truncate(time.Minute).String(),
			Now:     now.Format("15:04:05"),
			Version: version,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("template: %v", err)
		}
	})
	return mux
}

// sparkline renders a 60-minute series as an inline SVG polyline.
func sparkline(v []uint32) template.HTML {
	const w, h = 150.0, 22.0
	if len(v) == 0 {
		return ""
	}
	max := uint32(1)
	for _, n := range v {
		if n > max {
			max = n
		}
	}
	var sb strings.Builder
	step := w / float64(len(v)-1)
	for i, n := range v {
		y := h - (float64(n)/float64(max))*(h-2) - 1
		fmt.Fprintf(&sb, "%.1f,%.1f ", float64(i)*step, y)
	}
	return template.HTML(fmt.Sprintf(
		`<svg class="spark" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none">`+
			`<polyline points="%s"/></svg>`, w, h, strings.TrimSpace(sb.String())))
}

func shortName(s string) string {
	s = strings.TrimSuffix(s, ".local")
	if len(s) > 38 {
		return s[:37] + "…"
	}
	return s
}

func commas(n uint64) string {
	s := fmt.Sprint(n)
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	sort.SliceStable(parts, func(i, j int) bool { return false })
	return strings.Join(parts, ",")
}

var tmpl = template.Must(template.New("dash").Funcs(template.FuncMap{
	"spark": sparkline,
	"short": shortName,
	"comma": commas,
}).Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="15">
<title>mcastwatch — {{.Iface}}</title>
<style>
:root{--bg:#fbfbfa;--fg:#1c1b19;--dim:#77736c;--line:#e4e1db;--card:#fff;
      --ok:#3f8f5f;--warn:#c98a16;--crit:#c0392b;--accent:#2f6f9f}
@media (prefers-color-scheme:dark){
:root{--bg:#16171a;--fg:#e8e6e3;--dim:#8e8a84;--line:#2a2c30;--card:#1d1f23;
      --ok:#5ab77e;--warn:#e0a83c;--crit:#e05c4c;--accent:#6aa9d8}}
*{box-sizing:border-box}
body{margin:0;padding:1.5rem;background:var(--bg);color:var(--fg);
 font:14px/1.5 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
h1{font-size:1.1rem;margin:0 0 .25rem;font-weight:600}
.sub{color:var(--dim);font-size:.85rem;margin-bottom:1.25rem}
.stats{display:flex;gap:2rem;flex-wrap:wrap;margin-bottom:1.25rem}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;
 padding:.6rem .9rem;min-width:120px}
.stat .n{font-size:1.4rem;font-weight:600;font-variant-numeric:tabular-nums}
.stat .l{color:var(--dim);font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;background:var(--card);
 border:1px solid var(--line);border-radius:8px;overflow:hidden}
th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;
 color:var(--dim);padding:.6rem .7rem;border-bottom:1px solid var(--line);font-weight:600}
td{padding:.55rem .7rem;border-bottom:1px solid var(--line);
 font-variant-numeric:tabular-nums;vertical-align:middle}
tr:last-child td{border-bottom:none}
.num{text-align:right}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85rem}
.dim{color:var(--dim)}
.badge{display:inline-block;width:.55rem;height:.55rem;border-radius:50%;margin-right:.45rem}
.ok .badge{background:var(--ok)}.warn .badge{background:var(--warn)}.crit .badge{background:var(--crit)}
tr.crit td{background:color-mix(in srgb,var(--crit) 8%,transparent)}
tr.crit .num.rate{color:var(--crit);font-weight:600}
tr.warn .num.rate{color:var(--warn)}
.spark{width:150px;height:22px;display:block}
.spark polyline{fill:none;stroke:var(--accent);stroke-width:1.2;
 vector-effect:non-scaling-stroke;stroke-linejoin:round}
tr.crit .spark polyline{stroke:var(--crit)}
a{color:var(--accent)}
footer{margin-top:1.25rem;color:var(--dim);font-size:.78rem}
@media(max-width:820px){.hide-sm{display:none}body{padding:1rem}}
</style></head><body>
<h1>Multicast chatter on {{.Iface}}</h1>
<div class="sub">Updated {{.Now}} · running {{.Since}} · warn ≥{{.Warn}}/s · alert ≥{{.Crit}}/s · auto-refresh 15s</div>

<div class="stats">
  <div class="stat"><div class="n">{{.Hosts}}</div><div class="l">talkers</div></div>
  <div class="stat"><div class="n">{{.PPM}}</div><div class="l">pkts last min</div></div>
  <div class="stat"><div class="n">{{comma .AllTime}}</div><div class="l">pkts total</div></div>
</div>

<table>
<thead><tr>
  <th>Source</th><th class="hide-sm">Proto</th><th class="hide-sm">Top name</th>
  <th class="num">pkt/s</th><th class="num hide-sm">1h avg</th>
  <th class="num hide-sm">24h</th><th class="hide-sm">Last hour</th>
</tr></thead>
<tbody>
{{range .Rows}}
<tr class="{{.Status}}">
  <td><span class="badge"></span><span class="mono">{{.Key}}</span>
      {{if and .Hostname (ne .Hostname "-")}}<br><span class="dim mono">{{.Hostname}}</span>{{end}}</td>
  <td class="hide-sm dim">{{.Proto}}</td>
  <td class="hide-sm mono dim">{{if .Name}}{{short .Name}}{{else}}—{{end}}</td>
  <td class="num rate">{{printf "%.2f" .PPSNow}}</td>
  <td class="num hide-sm dim">{{printf "%.2f" .PPSHour}}</td>
  <td class="num hide-sm dim">{{comma .Day}}</td>
  <td class="hide-sm">{{spark .Spark}}</td>
</tr>
{{else}}
<tr><td colspan="7" class="dim">No traffic captured yet. Multicast is bursty; give it a minute.</td></tr>
{{end}}
</tbody></table>

<footer>mcastwatch {{.Version}} · <a href="/api/hosts">JSON</a></footer>
</body></html>`))
