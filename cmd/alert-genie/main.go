package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/alert-genie/alert-genie/internal/alert"
	"github.com/alert-genie/alert-genie/internal/analyzer"
	"github.com/alert-genie/alert-genie/internal/approval"
	"github.com/alert-genie/alert-genie/internal/config"
	"github.com/alert-genie/alert-genie/internal/executor"
	"github.com/alert-genie/alert-genie/internal/metrics"
	"github.com/alert-genie/alert-genie/internal/notifier"
	"github.com/alert-genie/alert-genie/internal/pipeline"
	"github.com/alert-genie/alert-genie/internal/safety"
	"github.com/alert-genie/alert-genie/internal/server"
	"github.com/alert-genie/alert-genie/internal/store"
	"github.com/alert-genie/alert-genie/internal/topology"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	flag.Parse()

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Setup logger
	logger := setupLogger(cfg.Logging)
	slog.SetDefault(logger)

	// Initialize store
	var st store.Store
	switch cfg.Store.Driver {
	case "sqlite":
		st, err = store.NewSQLite(cfg.Store.SQLitePath)
	case "postgres":
		st, err = store.NewPostgres(cfg.Store.PostgresDSN, cfg.Store.MaxOpenConns, cfg.Store.MaxIdleConns, cfg.Store.ConnMaxLifetime)
	default:
		logger.Error("unsupported store driver", "driver", cfg.Store.Driver)
		os.Exit(1)
	}
	if err != nil {
		logger.Error("failed to initialize store", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	// Run migrations
	if err := st.Migrate(context.Background()); err != nil {
		logger.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}
	logger.Info("database migrations completed")

	// Initialize components
	fetcher := metrics.NewPrometheusFetcher(cfg.Prometheus.Address, cfg.Prometheus.QueryTimeout)

	az := analyzer.NewClaudeAnalyzer(
		cfg.Claude.BaseURL, cfg.Claude.APIKey, cfg.Claude.Model,
		cfg.Claude.MaxTokens, cfg.Claude.Temperature, cfg.Claude.Timeout,
		cfg.Claude.MaxRetries, cfg.Claude.RetryBackoff,
	)

	sv := safety.NewValidator(nil, nil, logger)

	am := approval.NewManager(st, logger)

	larkNotifier := notifier.NewLarkNotifier(cfg.Lark.AppID, cfg.Lark.AppSecret, cfg.Lark.AlertChatID)

	topo, err := topology.NewStaticProvider(cfg.Topology.ConfigPath)
	if err != nil {
		logger.Warn("failed to load topology, continuing without it", "error", err)
		topo, _ = topology.NewStaticProvider("")
	}

	// Initialize executors
	executors := make(map[executor.CommandType]executor.Executor)

	for _, cluster := range cfg.Kubernetes.Clusters {
		k8sExec := executor.NewK8sExecutor(
			cluster.Name, cluster.KubeconfigPath, cluster.Context,
			cluster.AllowedNamespaces, logger,
		)
		executors[executor.CommandTypeK8s] = k8sExec
	}

	if len(cfg.SSH.Targets) > 0 {
		sshTargets := make([]executor.SSHTargetConfig, len(cfg.SSH.Targets))
		for i, t := range cfg.SSH.Targets {
			sshTargets[i] = executor.SSHTargetConfig{
				Name:           t.Name,
				Host:           t.Host,
				Port:           t.Port,
				User:           t.User,
				PrivateKeyPath: t.PrivateKeyPath,
				BastionHost:    t.BastionHost,
				BastionUser:    t.BastionUser,
				BastionKeyPath: t.BastionKeyPath,
			}
		}
		sshExec, err := executor.NewSSHExecutor(sshTargets, logger)
		if err != nil {
			logger.Warn("failed to initialize SSH executor", "error", err)
		} else {
			executors[executor.CommandTypeSSH] = sshExec
		}
	}

	router := executor.NewRouter(executors, st, larkNotifier, logger)

	// Initialize pipeline
	pipe := pipeline.New(cfg, fetcher, az, sv, am, router, larkNotifier, st, topo, logger)

	// Initialize alert handler
	dedup := alert.NewDeduplicator(cfg.Alertmanager.DedupWindow)
	defer dedup.Stop()

	alertHandler := alert.NewHandler(st, dedup, cfg.Alertmanager.SeverityFilter, logger)
	alertHandler.ProcessFunc = pipe.ProcessAlert

	// Initialize Lark callback handler
	callbackHandler := notifier.NewCallbackHandler(
		cfg.Lark.VerificationToken,
		pipe.HandleApprovalCallback,
	)

	// Initialize server
	srv := server.New(cfg, st, logger)

	// Register additional routes on the server's router
	srv.Router().Post("/api/v1/alerts", alertHandler.HandleWebhook)
	srv.Router().Post("/api/v1/lark/callback", callbackHandler.HandleCallback)

	// Start background tasks
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pipe.StartExpireLoop(ctx)

	// Start server
	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	logger.Info("alert-genie started",
		"mode", cfg.Mode,
		"addr", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		"store", cfg.Store.Driver,
		"clusters", len(cfg.Kubernetes.Clusters),
		"ssh_targets", len(cfg.SSH.Targets),
	)

	<-ctx.Done()
	logger.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown error", "error", err)
	}
	logger.Info("alert-genie stopped")
}

func setupLogger(cfg config.LoggingConfig) *slog.Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
