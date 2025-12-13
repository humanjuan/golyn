package main

import (
	"errors"
	"fmt"
	"golyn/app"
	"golyn/config/loaders"
	"golyn/database"
	"golyn/globals"
	"golyn/internal"
	"golyn/internal/cli"
	"golyn/internal/handlers"
	"golyn/internal/utils"
	"golyn/middlewares"
	"golyn/routes"
	"golyn/routes/virtualhosts"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
)

// Documentation: https://gin-gonic.com/docs/quickstart/

const (
	version    string = "v1.2.1"
	mainDomain string = "humanjuan.com"
)

func main() {
	// RUN CLI COMMAND BASED ON FLAGS
	exitCode, err, useFlag := cli.RunCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(exitCode)
	}
	if useFlag {
		os.Exit(exitCode)
	}

	// LOAD CONFIG
	conf, err := loaders.LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("[ERROR] An error occurred while trying to load the server configuration. %v", err))
	}
	globals.SetConfig(conf)

	// LOGGER
	logApp, err := loaders.InitLog(strings.ToLower(conf.Server.Name), conf.Log.Path, conf.Log.Level, conf.Log.MaxSizeMb, conf.Log.MaxBackup)
	if err != nil {
		panic(fmt.Sprintf("main() | Logger (Server) initialization failed | Error: %v", err.Error()))
	}
	logDB, err := loaders.InitLogDB(strings.ToLower(conf.Server.Name), conf.Log.Path, conf.Log.Level, conf.Log.MaxSizeMb, conf.Log.MaxBackup)
	if err != nil {
		panic(fmt.Sprintf("main() | Logger (DB) initialization failed | Error: %v", err.Error()))
	}
	defer logApp.Close()
	defer logDB.Close()

	// CONFIG GLOBAL LOGGER
	globals.SetAppLogger(logApp)
	globals.SetDBLogger(logDB)

	pid := os.Getpid()
	fmt.Printf("Welcome Back! - %v Server %v  - PID %v \n", conf.Server.Name, version, pid)
	logApp.Info("Welcome Back! - %v Server %v  - PID %v", conf.Server.Name, version, pid)

	// START DB CONNECTION
	dbInstance := database.NewDBInstance()

	if err = dbInstance.InitDB(&conf.Database, logApp); err != nil {
		logDB.Error("main() | An error occurred while establishing the connection to the database. | Error: %v", err.Error())
	}
	defer dbInstance.Close()

	globals.SetDBInstance(dbInstance)

	// LOAD CERTIFICATES
	globals.InitCertificates()
	if err = internal.LoadAllCertificates(conf.Sites); err != nil {
		logApp.Error("main() | An error has occurred while loading certificates. | Error: %v", err.Error())
	}

	logApp.Debug("main() | globals.InvalidCertificates: %v", globals.InvalidCertificates)

	// GET PUBLIC IP
	publicIP, localIP, err := utils.GetIPAddresses()
	if err != nil {
		logApp.Error("main() | An error occurred while fetching the public IP address. Error: %v", err.Error())
	}

	logApp.Info("main() | Dev mode: %t | Server Name: %s | Server port: %d | Local IP: %s | Public IP: %s",
		conf.Server.Dev, conf.Server.Name, conf.Server.Port, localIP, publicIP)

	// SERVER MODE
	if conf.Server.Dev {
		logApp.Warn("main() | Running in 'dev' mode. Switch 'dev = false' in conf file to production.")
		gin.SetMode(gin.DebugMode)
	} else {
		logApp.Info("main() | Running in 'Production' mode.")
		gin.SetMode(gin.ReleaseMode)
	}

	// PERFORMANCE GOROUTINE CONFIGURATION
	maxCPUCore := runtime.NumCPU()
	maxGoroutinesInParallel := maxCPUCore

	if conf.Server.MaxGoRoutineParallel != 0 && conf.Server.MaxGoRoutineParallel < maxCPUCore {
		maxGoroutinesInParallel = conf.Server.MaxGoRoutineParallel
	}
	logApp.Info("main() | Total Server CPU cores: %d | Total number of goroutines configured to run in parallel: %d", maxCPUCore, maxGoroutinesInParallel)

	runtime.GOMAXPROCS(maxGoroutinesInParallel)

	if conf.Server.MaxGoRoutineParallel != maxCPUCore && conf.Server.MaxGoRoutineParallel != 0 {
		logApp.Warn("main() | For best performance, the CPU cores and GoRoutine should have the same value.")
	}

	// INFO
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

	// START GIN FRAMEWORK
	serverRouter := gin.Default()

	// VIRTUAL HOSTS
	globals.VirtualHosts = virtualhosts.Setup(serverRouter)
	proxyMap := virtualhosts.BuildProxyHostMap(conf.Sites)

	// LOAD ERROR TEMPLATE
	err = handlers.LoadErrorTemplate(globals.DefaultSite)
	if err != nil {
		globals.RenderTemplate = false
	}

	// APPLY MIDDLEWARE
	// CREATE SERVER CACHE AND APPLY MORE MIDDLEWARE
	if conf.Cache.ExpirationTime == 0 {
		serverRouter.Use(middlewares.CacheMiddleware(cache.New(cache.NoExpiration, 0)))
		logApp.Info("main() | The server cache has been configured with No expiration time and without clean " +
			"up interval.")
	} else {
		serverRouter.Use(middlewares.CacheMiddleware(
			cache.New(
				time.Duration(conf.Cache.ExpirationTime)*time.Minute,
				time.Duration(conf.Cache.CleanUpInterval)*time.Minute,
			)),
		)
		logApp.Info("main() | The server cache has been configured with an expiration time of %v minutes and %v minutes "+
			"to clean up interval.", conf.Cache.ExpirationTime, conf.Cache.CleanUpInterval)
	}
	serverRouter.Use(middlewares.LoggingMiddleware())
	serverRouter.Use(middlewares.CustomErrorHandler())
	serverRouter.Use(middlewares.CompressionMiddleware())
	serverRouter.Use(virtualhosts.CreateDynamicProxyHandler(proxyMap))
	serverRouter.Use(middlewares.SecureMiddleware(conf.Server.Dev))
	serverRouter.Use(middlewares.RedirectOrAllowHostMiddleware())
	serverRouter.Use(middlewares.CorsMiddleware(conf.Sites))
	serverRouter.Use(middlewares.ClientCacheMiddleware(conf.Server.Dev))

	routes.ConfigureRoutes(serverRouter, serverInfo, mainDomain, conf.Server.Dev)

	// SET INITIAL SERVER PARAMETERS FOR SITES SERVER
	serverHTTPS, err := internal.SetupServerHTTPS(serverRouter)
	if err != nil {
		logApp.Warn("main() | No valid certificates found globally, but HTTPS server will handle errors. Falling back to HTTP for invalid sites. | Error: %v", err.Error())
	}
	logApp.Info("main() | TLS server configured on port %d", conf.Server.Port)

	// START HTTP TO HTTPS REDIRECT OR FALLBACK
	serverHTTP, err := internal.SetupServerHTTP(serverRouter)
	if err != nil {
		logApp.Error("main() | An error has occurred while trying to configure the HTTP server. | Error: %v", err.Error())
		panic(err.Error())
	}
	logApp.Info("main() | Server HTTP to redirect it's Up on port 80")

	mode := "Release"
	if conf.Server.Dev {
		mode = "Development"
	}

	var wg sync.WaitGroup

	// START HTTPS SERVER
	if serverHTTPS != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logApp.Debug("main() | Starting HTTPS server on %s (%v mode)", serverHTTPS.Addr, mode)
			err := serverHTTPS.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logApp.Error("main() | An error has occurred while trying to start the HTTPS server. | Error: %v", err.Error())
				os.Exit(1)
			}
		}()
	} else {
		logApp.Warn("main() | HTTPS server not started due to no valid certificates globally.")
	}

	// START HTTP SERVER
	wg.Add(1)
	go func() {
		defer wg.Done()
		if serverHTTP == nil {
			logApp.Error("main() | serverHTTP is nil in HTTP server goroutine")
			os.Exit(1)
			return
		}
		logApp.Debug("main() | Starting HTTP server on %s", serverHTTP.Addr)
		err = serverHTTP.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logApp.Error("main() | An error has occurred while trying to start the HTTP server. | Error: %v", err.Error())
			os.Exit(1)
		}
	}()

	// SHUTDOWN HANDLER
	wg.Add(1)
	go func() {
		defer wg.Done()
		internal.CatchSignalDual(serverHTTPS, serverHTTP)
	}()

	wg.Wait()
	logApp.Info("main() | Server exited.")

}
