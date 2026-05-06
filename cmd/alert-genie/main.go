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
	"github.com/alert-genie/alert-genie/internal/blastradius"
	"github.com/alert-genie/alert-genie/internal/chat"
	"github.com/alert-genie/alert-genie/internal/config"
	"github.com/alert-genie/alert-genie/internal/correlation"
	"github.com/alert-genie/alert-genie/internal/executor"
	"github.com/alert-genie/alert-genie/internal/incidents"
	"github.com/alert-genie/alert-genie/internal/metrics"
	"github.com/alert-genie/alert-genie/internal/notifier"
	"github.com/alert-genie/alert-genie/internal/pipeline"
	"github.com/alert-genie/alert-genie/internal/runbooks"
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

	// Build optional enrichment components. Each returns nil when disabled.
	historicalRetriever := buildRetriever(st, az, cfg, logger)
	runbookRetriever := buildRunbookRetriever(cfg, logger)
	blastRadiusAssessor := buildBlastRadiusAssessor(fetcher, topo, cfg, logger)

	// Pipeline first; the correlator's onGroup callback needs to reference
	// pipeline.processGroup, so we construct the pipeline with a nil correlator,
	// then build the correlator (if enabled) referencing pipe, and inject it back.
	pipe := pipeline.New(cfg, fetcher, az, sv, am, router, larkNotifier, st, topo,
		historicalRetriever, runbookRetriever, nil, blastRadiusAssessor, logger)

	correlator := buildCorrelator(cfg, topo, pipe, logger)
	pipe.SetCorrelator(correlator)

	// Initialize alert handler
	dedup := alert.NewDeduplicator(cfg.Alertmanager.DedupWindow)
	defer dedup.Stop()

	alertHandler := alert.NewHandler(st, dedup, cfg.Alertmanager.SeverityFilter, logger)
	alertHandler.ProcessFunc = pipe.ProcessAlert

	// Initialize Lark callback handler (card button clicks)
	callbackHandler := notifier.NewCallbackHandler(
		cfg.Lark.VerificationToken,
		pipe.HandleApprovalCallback,
	)
	callbackHandler.SetFeedbackHandler(pipe.HandleFeedbackCallback)

	// Initialize chat orchestrator (multi-turn conversations triggered by @Bot)
	chatOrchestrator := chat.New(st, az, larkNotifier, am, sv, cfg.Approval.TTL, logger)

	// Initialize server
	srv := server.New(cfg, st, logger)

	// Register additional routes on the server's router
	srv.Router().Post("/api/v1/alerts", alertHandler.HandleWebhook)
	srv.Router().Post("/api/v1/lark/callback", callbackHandler.HandleCallback)

	// Conditionally register the chat event endpoint
	if cfg.Lark.ChatEnabled {
		eventHandler := notifier.NewEventHandler(
			cfg.Lark.VerificationToken,
			cfg.Lark.BotOpenID,
			cfg.Lark.BotName,
			st, // store implements EventDeduper via MarkEventProcessed
			chatOrchestrator.HandleEvent,
		)
		srv.Router().Post("/api/v1/lark/events", eventHandler.HandleEvent)
		logger.Info("@Bot chat enabled", "bot_open_id", cfg.Lark.BotOpenID)
	} else {
		logger.Info("@Bot chat disabled (set lark.chat_enabled: true to enable)")
	}

	// Start background tasks
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pipe.StartExpireLoop(ctx)

	// Start the alert correlator background loop if it was built
	if correlator != nil {
		correlator.Start(ctx)
		defer correlator.Stop()
	}

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

// buildRetriever constructs the historical incident retriever, returning nil
// when disabled in config so the pipeline can skip that pass cleanly.
func buildRetriever(st store.Store, az analyzer.Analyzer, cfg *config.Config, logger *slog.Logger) incidents.Retriever {
	if !cfg.Historical.Enabled {
		logger.Info("historical incident retriever disabled (set historical.enabled: true to enable)")
		return nil
	}
	logger.Info("historical incident retriever enabled",
		"candidate_pool_size", cfg.Historical.CandidatePoolSize,
		"top_k", cfg.Historical.TopK,
		"lookback_days", cfg.Historical.LookbackDays,
	)
	ranker := &incidents.AnalyzerRanker{A: az}
	return incidents.New(st, ranker, incidents.Config{
		CandidatePoolSize:   cfg.Historical.CandidatePoolSize,
		TopK:                cfg.Historical.TopK,
		LookbackDays:        cfg.Historical.LookbackDays,
		MinCandidatesForLLM: cfg.Historical.MinCandidatesForLLM,
		Enabled:             true,
	}, logger)
}

// buildRunbookRetriever constructs the runbook KB and starts its background
// reload loop, returning a Retriever or nil when disabled.
func buildRunbookRetriever(cfg *config.Config, logger *slog.Logger) runbooks.Retriever {
	if !cfg.Runbooks.Enabled || cfg.Runbooks.Directory == "" {
		logger.Info("runbook KB disabled (set runbooks.enabled: true and runbooks.directory to enable)")
		return nil
	}
	logger.Info("runbook KB enabled",
		"directory", cfg.Runbooks.Directory,
		"reload_interval", cfg.Runbooks.ReloadInterval,
		"top_k", cfg.Runbooks.TopK,
	)
	loader := runbooks.NewFSLoader(cfg.Runbooks.Directory)
	st := runbooks.NewStore(loader, logger)
	if err := st.Start(context.Background(), cfg.Runbooks.ReloadInterval); err != nil {
		logger.Warn("initial runbook load failed; KB starts empty",
			"error", err, "directory", cfg.Runbooks.Directory)
	}
	return runbooks.NewRetriever(st, runbooks.Config{
		Enabled:         true,
		TopK:            cfg.Runbooks.TopK,
		MaxExcerptChars: 2000,
	})
}

// buildCorrelator builds the alert correlator if enabled. nil otherwise.
// The pipe is needed because the correlator's onGroup callback is
// pipe.ProcessGroup.
func buildCorrelator(cfg *config.Config, topo topology.Provider, pipe *pipeline.Pipeline, logger *slog.Logger) *correlation.Correlator {
	if !cfg.Correlation.Enabled {
		logger.Info("alert correlation disabled (set correlation.enabled: true to enable)")
		return nil
	}
	logger.Info("alert correlation enabled",
		"window", cfg.Correlation.Window,
		"max_group_size", cfg.Correlation.MaxGroupSize,
	)
	return correlation.New(
		cfg.Correlation.Window,
		cfg.Correlation.MaxGroupSize,
		topo,
		pipe.ProcessGroup,
		logger,
	)
}

// buildBlastRadiusAssessor constructs the blast-radius assessor if enabled.
func buildBlastRadiusAssessor(fetcher metrics.Fetcher, topo topology.Provider, cfg *config.Config, logger *slog.Logger) blastradius.Assessor {
	if !cfg.BlastRadius.Enabled {
		logger.Info("blast radius assessor disabled (set blast_radius.enabled: true to enable)")
		return nil
	}
	logger.Info("blast radius assessor enabled",
		"query_timeout", cfg.BlastRadius.QueryTimeout,
		"high_traffic_threshold", cfg.BlastRadius.HighTrafficThreshold,
		"critical_traffic_threshold", cfg.BlastRadius.CriticalTrafficThreshold,
		"auto_upgrade_risk_level", cfg.BlastRadius.AutoUpgradeRiskLevel,
	)
	return blastradius.New(fetcher, topo, blastradius.Config{
		Enabled:                  true,
		PrometheusQueryTimeout:   cfg.BlastRadius.QueryTimeout,
		HighTrafficThreshold:     cfg.BlastRadius.HighTrafficThreshold,
		CriticalTrafficThreshold: cfg.BlastRadius.CriticalTrafficThreshold,
	}, logger)
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
