package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/alert-genie/alert-genie/internal/config"
	"github.com/alert-genie/alert-genie/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	cfg    *config.Config
	store  store.Store
	router *chi.Mux
	logger *slog.Logger
	http   *http.Server
}

func New(cfg *config.Config, st store.Store, logger *slog.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		store:  st,
		logger: logger,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(LoggingMiddleware(logger))
	r.Use(RecoveryMiddleware(logger))

	// Health + metrics
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	r.Handle("/metrics", promhttp.Handler())

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Alerts
		r.Get("/alerts", s.handleListAlerts)
		r.Get("/alerts/{id}", s.handleGetAlert)

		// Approvals
		r.Get("/approvals", s.handleListApprovals)
		r.Get("/approvals/{id}", s.handleGetApproval)

		// Executions
		r.Get("/executions/{approvalID}", s.handleListExecutionLogs)

		// Safety
		r.Post("/safety/validate", s.handleValidateCommand)

		// Config
		r.Get("/config", s.handleGetConfig)
	})

	s.router = r
	return s
}

// Router returns the chi router for external route registration (webhook, callback).
func (s *Server) Router() *chi.Mux {
	return s.router
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)
	s.http = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  s.cfg.Server.ReadTimeout,
		WriteTimeout: s.cfg.Server.WriteTimeout,
	}
	s.logger.Info("starting server", "addr", addr)
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// Handlers

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	// Check store connectivity
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	_, err := s.store.ListAlerts(ctx, store.AlertFilter{Limit: 1})
	if err != nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	filter := store.AlertFilter{Limit: 50}
	if v := r.URL.Query().Get("status"); v != "" {
		filter.Status = &v
	}
	if v := r.URL.Query().Get("severity"); v != "" {
		filter.Severity = &v
	}
	if v := r.URL.Query().Get("alert_name"); v != "" {
		filter.AlertName = &v
	}

	alerts, err := s.store.ListAlerts(r.Context(), filter)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, alerts)
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	alert, err := s.store.GetAlert(r.Context(), id)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if alert == nil {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}

	analysis, _ := s.store.GetAnalysis(r.Context(), id)

	respondJSON(w, http.StatusOK, map[string]any{
		"alert":    alert,
		"analysis": analysis,
	})
}

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	filter := store.ApprovalFilter{Limit: 50}
	if v := r.URL.Query().Get("status"); v != "" {
		filter.Status = &v
	}

	approvals, err := s.store.ListApprovals(r.Context(), filter)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, approvals)
}

func (s *Server) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	approval, err := s.store.GetApproval(r.Context(), id)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if approval == nil {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "approval not found"})
		return
	}

	logs, _ := s.store.ListExecutionLogs(r.Context(), id)

	respondJSON(w, http.StatusOK, map[string]any{
		"approval":       approval,
		"execution_logs": logs,
	})
}

func (s *Server) handleListExecutionLogs(w http.ResponseWriter, r *http.Request) {
	approvalID := chi.URLParam(r, "approvalID")
	logs, err := s.store.ListExecutionLogs(r.Context(), approvalID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, logs)
}

func (s *Server) handleValidateCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Command     string `json:"command"`
		CommandType string `json:"command_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	// Safety validator will be wired in later phases
	respondJSON(w, http.StatusOK, map[string]string{"status": "validator not yet initialized"})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	// Return config with secrets redacted
	safe := *s.cfg
	safe.Claude.APIKey = "***"
	safe.Lark.AppSecret = "***"
	safe.Lark.VerificationToken = "***"
	safe.Lark.EncryptionKey = "***"
	for i := range safe.SSH.Targets {
		safe.SSH.Targets[i].PrivateKeyPath = "***"
		safe.SSH.Targets[i].BastionKeyPath = "***"
	}
	respondJSON(w, http.StatusOK, safe)
}
