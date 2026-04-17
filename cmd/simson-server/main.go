package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nitish-mp3/simson-vps/admin"
	"github.com/nitish-mp3/simson-vps/asterisk"
	"github.com/nitish-mp3/simson-vps/config"
	"github.com/nitish-mp3/simson-vps/logging"
	"github.com/nitish-mp3/simson-vps/server"
	"github.com/nitish-mp3/simson-vps/store"
)

func main() {
	// --- Config ---
	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	// Allow env overrides for sensitive values.
	if tok := os.Getenv("SIMSON_ADMIN_TOKEN"); tok != "" {
		cfg.AdminToken = tok
	}
	if dbPath := os.Getenv("SIMSON_DB_PATH"); dbPath != "" {
		cfg.DBPath = dbPath
	}
	if listen := os.Getenv("SIMSON_LISTEN"); listen != "" {
		cfg.Listen = listen
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config validation: %v\n", err)
		os.Exit(1)
	}

	// --- Logger ---
	log := logging.New(cfg.LogLevel)
	log.Info("starting simson control plane", map[string]any{
		"listen":  cfg.Listen,
		"db":      cfg.DBPath,
	})

	// --- Store ---
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Error("failed to open database", map[string]any{"err": err.Error()})
		os.Exit(1)
	}
	defer st.Close()

	// --- Server ---
	srv := server.New(cfg, st, log)

	// --- Asterisk auto-configure (runs before background tasks so confs are ready) ---
	if cfg.Asterisk.Enabled && cfg.Asterisk.AutoConfigure {
		eps, err := st.ListAllSIPEndpoints()
		if err != nil {
			log.Warn("asterisk auto-configure: failed to load SIP endpoints", map[string]any{"err": err.Error()})
		} else {
			defs := make([]asterisk.SIPEndpointDef, len(eps))
			for i, ep := range eps {
				defs[i] = asterisk.SIPEndpointDef{
					ID:        ep.ID,
					Extension: ep.Extension,
					Username:  ep.Username,
					Password:  ep.Password,
					Enabled:   ep.Enabled,
				}
			}
			scfg := asterisk.SetupConfig{
				AmiUser:     cfg.Asterisk.User,
				AmiSecret:   cfg.Asterisk.Secret,
				SIPDomain:   cfg.Asterisk.SIPDomain,
				ExternalIP:  cfg.Asterisk.ExternalIP,
				InContext:   cfg.Asterisk.InContext,
				NodeContext: cfg.Asterisk.NodeContext,
				WebRTCUser:  cfg.Asterisk.SIPWebRTC.Username,
				WebRTCPass:  cfg.Asterisk.SIPWebRTC.Password,
			}
			if err := asterisk.Setup(scfg, defs, log); err != nil {
				log.Warn("asterisk auto-configure failed (continuing)", map[string]any{"err": err.Error()})
			} else {
				log.Info("asterisk auto-configure complete", nil)
			}
		}
	}

	srv.StartBackgroundTasks()

	// --- Admin API ---
	adminAPI := admin.New(cfg, st, srv.Hub(), srv.Calls(), log)
	if srv.Asterisk() != nil {
		adminAPI.SetAsterisk(srv.Asterisk())
	}

	// --- HTTP Router ---
	mux := http.NewServeMux()

	// WebSocket endpoint.
	mux.HandleFunc("/ws", srv.HandleWS)

	// Admin endpoints.
	adminRouter := adminAPI.Router()
	mux.Handle("/admin/", adminRouter)

	// Metrics endpoint (basic, protected by admin token).
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if len(token) > 7 {
			token = token[7:] // strip "Bearer "
		}
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(cfg.AdminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "# HELP simson_connected_nodes Number of connected nodes\n")
		fmt.Fprintf(w, "# TYPE simson_connected_nodes gauge\n")
		fmt.Fprintf(w, "simson_connected_nodes %d\n", srv.Hub().Count())
		fmt.Fprintf(w, "# HELP simson_active_calls Number of active calls\n")
		fmt.Fprintf(w, "# TYPE simson_active_calls gauge\n")
		fmt.Fprintf(w, "simson_active_calls %d\n", len(srv.Calls().ListAll()))
	})

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// --- Graceful shutdown ---
	done := make(chan os.Signal, 1)
	listenErr := make(chan error, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		var err error
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			log.Info("listening with TLS", map[string]any{"addr": cfg.Listen})
			err = httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			log.Info("listening (plain HTTP — use Caddy for TLS)", map[string]any{"addr": cfg.Listen})
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			listenErr <- err
		}
	}()

	select {
	case <-done:
		log.Info("shutting down", nil)
	case err := <-listenErr:
		log.Error("listen error", map[string]any{"err": err.Error()})
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)

	log.Info("stopped", nil)
}
