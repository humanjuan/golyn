package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/humanjuan/golyn/app"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/database"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal"
	"github.com/humanjuan/golyn/internal/cli"
	internalcfg "github.com/humanjuan/golyn/internal/config"
	"github.com/humanjuan/golyn/internal/handlers"
	"github.com/humanjuan/golyn/internal/utils"
	"github.com/humanjuan/golyn/lifecycle"
	"github.com/humanjuan/golyn/middlewares"
	"github.com/humanjuan/golyn/routes"
	"github.com/humanjuan/golyn/routes/virtualhosts"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"

	_ "github.com/humanjuan/golyn-ai/register"
)

// Documentation: https://gin-gonic.com/docs/quickstart/

const (
	version string = "v1.6.0"
)

func main() {
	// CLI flags
	exitCode, err, useFlag, noExtensions := cli.RunCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(exitCode)
	}
	if useFlag {
		os.Exit(exitCode)
	}

	lifecycle.NoExtensions = noExtensions

	conf, err := loaders.LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("[ERROR] Failed to load server configuration: %v", err))
	}
	globals.SetConfig(conf)
	lifecycle.Init()

	logApp, err := loaders.InitLog(strings.ToLower(conf.Server.Name), conf.Log.Path, conf.Log.Level, conf.Log.MaxSizeMb, conf.Log.MaxBackup, conf.Log.DailyRotation)
	if err != nil {
		panic(fmt.Sprintf("main() | Server logger init failed: %v", err.Error()))
	}
	logDB, err := loaders.InitLogDB(strings.ToLower(conf.Server.Name), conf.Log.Path, conf.Log.Level, conf.Log.MaxSizeMb, conf.Log.MaxBackup, conf.Log.DailyRotation)
	if err != nil {
		panic(fmt.Sprintf("main() | DB logger init failed: %v", err.Error()))
	}
	defer logApp.Close()
	defer logDB.Close()

	globals.SetAppLogger(logApp)
	globals.SetDBLogger(logDB)

	pid := os.Getpid()
	fmt.Printf("Welcome back! - %v Server %v - PID %v\n", conf.Server.Name, version, pid)
	logApp.Info("Welcome back! - %v Server %v - PID %v", conf.Server.Name, version, pid)

	dbInstance := database.NewDBInstance()

	if err = dbInstance.InitDB(&conf.Database, logDB); err != nil {
		logDB.Error("main() | Database connection error: %v", err.Error())
		logDB.Sync()
	}
	defer dbInstance.Close()

	globals.SetDBInstance(dbInstance)

	globals.InitCertificates()
	if err = internal.LoadAllCertificates(conf.Sites); err != nil {
		logApp.Error("main() | Certificate loading error: %v", err.Error())
		logApp.Sync()
	}

	logApp.Debug("main() | globals.InvalidCertificates: %v", globals.InvalidCertificates)

	publicIP, localIP, err := utils.GetIPAddresses()
	if err != nil {
		logApp.Error("main() | Failed to fetch public IP: %v", err.Error())
		logApp.Sync()
	}

	logApp.Info("main() | Dev mode: %t | Server: %s | Port: %d | Local IP: %s | Public IP: %s",
		conf.Server.Dev, conf.Server.Name, conf.Server.Port, localIP, publicIP)

	// Run mode
	if conf.Server.Dev {
		logApp.Warn("main() | Running in 'dev' mode. Set 'dev = false' in conf for production.")
		gin.SetMode(gin.DebugMode)
	} else {
		logApp.Info("main() | Running in 'production' mode.")
		gin.SetMode(gin.ReleaseMode)
	}

	// Concurrency settings
	maxCPUCore := runtime.NumCPU()
	maxGoroutinesInParallel := maxCPUCore

	if conf.Server.MaxGoRoutineParallel != 0 && conf.Server.MaxGoRoutineParallel < maxCPUCore {
		maxGoroutinesInParallel = conf.Server.MaxGoRoutineParallel
	}
	logApp.Info("main() | CPU Cores: %d | Configured parallel goroutines: %d", maxCPUCore, maxGoroutinesInParallel)

	runtime.GOMAXPROCS(maxGoroutinesInParallel)

	if conf.Server.MaxGoRoutineParallel != maxCPUCore && conf.Server.MaxGoRoutineParallel != 0 {
		logApp.Warn("main() | Tip: For best performance, match CPU cores and goroutine count.")
	}

	// Runtime info
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	memAllocatedInMB := float64(mem.Alloc) / 1024 / 1024

	var golynCertPath string
	for _, site := range conf.Sites {
		if site.Directory == "golyn" {
			golynCertPath = site.Security.TLS_SSL.Cert
		}
	}

	serverInfo := &app.Info{
		ServerVersion:           version,
		GinVersion:              gin.Version,
		GoVersion:               runtime.Version(),
		ServerStartTime:         time.Now(),
		CertificatePath:         golynCertPath,
		NumGoroutinesInParallel: runtime.GOMAXPROCS(0),
		MemStatsInMB:            memAllocatedInMB,
		NumCPU:                  runtime.NumCPU(),
	}

	// Initialize Gin
	serverRouter := gin.Default()

	// Set up virtual hosts
	globals.VirtualHosts = virtualhosts.Setup(serverRouter)
	proxyMap := virtualhosts.BuildProxyHostMap(conf.Sites)

	// Error templates
	err = handlers.LoadErrorTemplate(globals.DefaultSite)
	if err != nil {
		globals.RenderTemplate = false
	}

	// Setup Cache and Middlewares
	if conf.Cache.ExpirationTime == 0 {
		serverRouter.Use(middlewares.CacheMiddleware(cache.New(cache.NoExpiration, 0)))
		logApp.Info("main() | Server cache enabled (No expiration).")
	} else {
		serverRouter.Use(middlewares.CacheMiddleware(
			cache.New(
				time.Duration(conf.Cache.ExpirationTime)*time.Minute,
				time.Duration(conf.Cache.CleanUpInterval)*time.Minute,
			)),
		)
		logApp.Info("main() | Server cache enabled (Exp: %vm, Cleanup: %vm).", conf.Cache.ExpirationTime, conf.Cache.CleanUpInterval)
	}
	serverRouter.Use(middlewares.LoggingMiddleware())
	serverRouter.Use(middlewares.CustomErrorHandler())

	// Platform security headers + HTTPS enforcement + per-site dynamic config reload (hash-based)
	siteProvider := internalcfg.NewSiteProvider()
	serverRouter.Use(middlewares.SecurityHeadersMiddleware(siteProvider, conf.Server.Dev))
	serverRouter.Use(middlewares.RedirectOrAllowHostMiddleware())
	serverRouter.Use(middlewares.CorsMiddleware())
	serverRouter.Use(middlewares.ClientCacheMiddleware(conf.Server.Dev))

	serverRouter.Use(middlewares.CompressionMiddleware())
	serverRouter.Use(virtualhosts.CreateDynamicProxyHandler(proxyMap))

	routes.ConfigureRoutes(serverRouter, serverInfo, conf.Server.MainDomain, conf.Server.Dev)

	// Lifecycle Start
	lifecycle.NotifyRouterReady(serverRouter)
	ctx := context.Background()

	if err := lifecycle.Start(ctx); err != nil {
		logApp.Error("main() | Lifecycle start failed: %v", err)
		logApp.Sync()
		os.Exit(1)
	}

	// Server parameters
	serverHTTPS, err := internal.SetupServerHTTPS(serverRouter)
	if err != nil {
		logApp.Warn("main() | No valid certificates found, HTTPS will handle errors. Falling back to HTTP for some sites. | Error: %v", err.Error())
	}
	logApp.Info("main() | TLS server on port %d", conf.Server.Port)

	// Redirect server
	serverHTTP, err := internal.SetupServerHTTP(serverRouter)
	if err != nil {
		logApp.Error("main() | Failed to setup HTTP server: %v", err.Error())
		logApp.Sync()
		panic(err.Error())
	}
	if serverHTTP != nil {
		logApp.Info("main() | HTTP redirect server on port 80")
	} else {
		logApp.Info("main() | HTTP server is disabled (Production mode).")
	}

	mode := "Release"
	if conf.Server.Dev {
		mode = "Development"
	}

	var wg sync.WaitGroup

	// Start HTTPS
	if serverHTTPS != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logApp.Debug("main() | Starting HTTPS on %s (%v mode)", serverHTTPS.Addr, mode)
			err := serverHTTPS.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logApp.Error("main() | HTTPS server failed: %v", err.Error())
				logApp.Sync()
				os.Exit(1)
			}
		}()
	} else {
		logApp.Warn("main() | HTTPS not started (no certificates).")
	}

	// Start HTTP
	if serverHTTP != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logApp.Debug("main() | Starting HTTP on %s", serverHTTP.Addr)
			err = serverHTTP.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logApp.Error("main() | HTTP server failed: %v", err.Error())
				logApp.Sync()
				os.Exit(1)
			}
		}()
	}

	// Graceful shutdown
	wg.Add(1)
	go func() {
		defer wg.Done()
		internal.CatchSignalDual(serverHTTPS, serverHTTP)

		// Lifecycle Shutdown
		lifecycle.Shutdown(ctx)
	}()

	wg.Wait()
	logApp.Info("main() | Server stopped.")

}
