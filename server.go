package vercelreceiver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	"go.uber.org/zap"
)

// httpServer manages the HTTP server for receiving Vercel drain data
type httpServer struct {
	logger *zap.Logger
	cfg    *Config

	// Handlers for each drain type
	logsHandler          http.HandlerFunc
	tracesHandler        http.HandlerFunc
	speedInsightsHandler http.HandlerFunc
	analyticsHandler     http.HandlerFunc

	httpServer *http.Server
	mux        *http.ServeMux
	mu         sync.Mutex
}

// newHTTPServer creates a new HTTP server instance
func newHTTPServer(cfg *Config, logger *zap.Logger) *httpServer {
	s := &httpServer{
		logger: logger,
		cfg:    cfg,
		mux:    http.NewServeMux(),
	}

	return s
}

// registerHandlers registers all HTTP handlers for the server
func (s *httpServer) registerHandlers() {
	// Logs endpoint
	if s.logsHandler != nil {
		s.mux.HandleFunc("/logs", s.withSignatureAuth(s.cfg.Logs.Secret, s.logsHandler))
	}

	// Traces endpoint
	if s.tracesHandler != nil {
		s.mux.HandleFunc("/traces", s.withSignatureAuth(s.cfg.Traces.Secret, s.tracesHandler))
	}

	// Speed Insights endpoint
	if s.speedInsightsHandler != nil {
		s.mux.HandleFunc("/speed-insights", s.withSignatureAuth(s.cfg.SpeedInsights.Secret, s.speedInsightsHandler))
	}

	// Web Analytics endpoint
	if s.analyticsHandler != nil {
		s.mux.HandleFunc("/analytics", s.withSignatureAuth(s.cfg.WebAnalytics.Secret, s.analyticsHandler))
	}

	// Health check endpoint
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// withSignatureAuth wraps a handler with signature verification middleware
func (s *httpServer) withSignatureAuth(secret string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read body once
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			s.logger.Error("Failed to read request body", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Verify signature
		if err := verifyRequest(r, secret, bodyBytes); err != nil {
			s.logger.Warn("Signature verification failed", zap.Error(err))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		handler(w, r)
	}
}

// start starts the HTTP server
func (s *httpServer) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.registerHandlers()

	if s.httpServer != nil {
		return fmt.Errorf("server already started")
	}

	// Default to port 8080 if no endpoint is configured
	listenAddr := ":8080"
	if s.cfg.Logs.Endpoint != "" {
		listenAddr = s.cfg.Logs.Endpoint
	}

	s.httpServer = &http.Server{
		Addr:    listenAddr,
		Handler: s.mux,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server failed", zap.Error(err))
		}
	}()

	s.logger.Info("HTTP server started", zap.String("address", listenAddr))
	return nil
}

// shutdown gracefully shuts down the HTTP server
func (s *httpServer) shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.httpServer == nil {
		return nil
	}

	s.logger.Info("Shutting down HTTP server")
	return s.httpServer.Shutdown(ctx)
}
