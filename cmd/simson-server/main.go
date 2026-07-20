package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
		"listen": cfg.Listen,
		"db":     cfg.DBPath,
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
			accountFeatures, featureErr := st.ListAccountCallFeatures()
			if featureErr != nil {
				log.Warn("asterisk auto-configure: failed to load account call features", map[string]any{"err": featureErr.Error()})
			}
			featuresByAccount := make(map[string]store.AccountCallFeatures, len(accountFeatures))
			for _, features := range accountFeatures {
				featuresByAccount[features.AccountID] = features
			}
			defs := make([]asterisk.SIPEndpointDef, len(eps))
			for i, ep := range eps {
				features := featuresByAccount[ep.AccountID]
				defs[i] = asterisk.SIPEndpointDef{
					ID:                        ep.ID,
					AccountID:                 ep.AccountID,
					Extension:                 ep.Extension,
					Username:                  ep.Username,
					Password:                  ep.Password,
					RouteTo:                   ep.RouteTo,
					VideoEnabled:              ep.VideoEnabled,
					AutoAnswer:                ep.AutoAnswer,
					AutoAnswerCallers:         ep.AutoAnswerCallers,
					AutoSpeaker:               ep.AutoSpeaker,
					AutoSpeakerCallers:        ep.AutoSpeakerCallers,
					CallbackBridge:            ep.CallbackBridge,
					CallbackBridgeCallers:     ep.CallbackBridgeCallers,
					CallbackCallerAutoAnswer:  ep.CallbackCallerAutoAnswer,
					CallbackCallerAutoSpeaker: ep.CallbackCallerAutoSpeaker,
					GatewayIVREnabled:         ep.GatewayIVREnabled,
					GatewayIVRSound:           ep.GatewayIVRSound,
					AnswerAnnouncement:        ep.AnswerAnnouncement,
					PreRingAnnouncement:       ep.PreRingAnnouncement,
					CallDurationRules:         ep.CallDurationRules,
					SupervisionConfig:         ep.SupervisionConfig,
					AccountTransferCode:       features.TransferCode,
					AccountConferenceCode:     features.ConferenceCode,
					AccountFeaturesEnabled:    features.Enabled,
					Enabled:                   ep.Enabled,
				}
			}
			noAuthInbound := gatewayNoAuthInboundExtensions(cfg.Asterisk.NoAuthInboundExtensions, eps)
			scfg := asterisk.SetupConfig{
				AmiUser:                 cfg.Asterisk.User,
				AmiSecret:               cfg.Asterisk.Secret,
				SIPDomain:               cfg.Asterisk.SIPDomain,
				ExternalIP:              cfg.Asterisk.ExternalIP,
				InContext:               cfg.Asterisk.InContext,
				NodeContext:             cfg.Asterisk.NodeContext,
				OutContext:              cfg.Asterisk.OutContext,
				DefaultPSTNTrunk:        cfg.Asterisk.DefaultPSTNTrunk,
				TrustedGatewayIPs:       cfg.Asterisk.TrustedGatewayIPs,
				NoAuthInboundExtensions: noAuthInbound,
				WebRTCUser:              cfg.Asterisk.SIPWebRTC.Username,
				WebRTCPass:              cfg.Asterisk.SIPWebRTC.Password,
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
	mux.HandleFunc("/node/webrtc-config", srv.HandleNodeWebRTCConfig)
	mux.HandleFunc("/node/door-events", srv.HandleNodeDoorEvent)
	mux.HandleFunc("/node/door-node-events", srv.HandleNodeDoorNodeEvent)
	mux.HandleFunc("/node/sip-intercom", srv.HandleNodeSIPIntercom)

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
		srv.Shutdown()
	case err := <-listenErr:
		log.Error("listen error", map[string]any{"err": err.Error()})
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)

	log.Info("stopped", nil)
}

func gatewayNoAuthInboundExtensions(configured []string, endpoints []store.SIPEndpoint) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(configured)+len(endpoints))
	add := func(value string) {
		ext := strings.TrimSpace(value)
		if ext == "" || seen[ext] {
			return
		}
		seen[ext] = true
		out = append(out, ext)
	}
	for _, ext := range configured {
		add(ext)
	}
	for _, ep := range endpoints {
		if ep.Enabled && isGatewayNoAuthCandidate(ep.Extension) {
			add(ep.Extension)
		}
	}
	return out
}

func isGatewayNoAuthCandidate(extension string) bool {
	ext := strings.TrimSpace(extension)
	if len(ext) < 3 || len(ext) > 8 {
		return false
	}
	if !strings.HasPrefix(ext, "70") {
		return false
	}
	for _, ch := range ext {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
