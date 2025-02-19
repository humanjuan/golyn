package main

import (
	"Back/app"
	"Back/config/loaders"
	"Back/database"
	"Back/internal"
	"Back/internal/handlers"
	"Back/internal/utils"
	"Back/middlewares"
	"Back/routes"
	"Back/routes/virtualhosts"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"github.com/patrickmn/go-cache"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Documentation: https://gin-gonic.com/docs/quickstart/

const (
	version         string = "v1.0.0-16022025A"
	certificatePath string = "./certificates/cert.pem"
	certificateKey  string = "./certificates/privkey.pem"
	mainDomain      string = "humanjuan.com"
)

func main() {
	var log *logger.Log
	var logDB *logger.Log

	// LOAD CONFIG
	conf, err := loaders.LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("[ERROR] An error occurred while trying to load the server configuration. %v", err))
	}

	// LOGGER
	log, err = loaders.InitLog(strings.ToLower(conf.Server.Name), conf.Log.Path, conf.Log.Level, conf.Log.MaxSizeMb, conf.Log.MaxBackup)
	if err != nil {
		panic(fmt.Sprintf("Logger (Server) initialization failed: %v", err.Error()))
	}
	logDB, err = loaders.InitLogDB(strings.ToLower(conf.Server.Name), conf.Log.Path, conf.Log.Level, conf.Log.MaxSizeMb, conf.Log.MaxBackup)
	if err != nil {
		panic(fmt.Sprintf("Logger (DB) initialization failed: %v", err.Error()))
	}
	defer log.Close()
	defer logDB.Close()

	pid := os.Getpid()
	fmt.Printf("Welcome Back! - %v Server %v  - PID %v \n", conf.Server.Name, version, pid)
	log.Info("Welcome Back! - %v Server %v  - PID %v", conf.Server.Name, version, pid)

	// START DB CONNECTION
	dbInstance := database.NewDBInstance()

	if err := dbInstance.InitDB(conf, logDB); err != nil {
		log.Error("An error occurred while establishing the connection to the database.")
	}
	defer dbInstance.Close()

	globalApp := &app.Application{
		DB:     dbInstance,
		LogDB:  logDB,
		LogApp: log,
		Config: conf,
	}

	certificate := &app.Cert{
		Path: certificatePath,
		Key:  certificateKey,
	}

	// GET PUBLIC IP
	publicIP, localIP := utils.GetIPAddresses(globalApp.LogApp)

	log.Info("Dev mode: %t | Server Name: %s | Server port: %d | Local IP: %s | Public IP: %s",
		conf.Server.Dev, conf.Server.Name, conf.Server.Port, localIP, publicIP)

	// SERVER MODE
	if conf.Server.Dev {
		log.Warn("Running in 'dev' mode. Switch 'dev = false' in conf file to production.")
		gin.SetMode(gin.DebugMode)
	} else {
		log.Info("Running in 'Production' mode.")
		gin.SetMode(gin.ReleaseMode)
	}

	// PERFORMANCE GOROUTINE CONFIGURATION
	maxCPUCore := runtime.NumCPU()
	maxGoroutinesInParallel := maxCPUCore

	if conf.Server.MaxGoRoutineParallel != 0 && conf.Server.MaxGoRoutineParallel < maxCPUCore {
		maxGoroutinesInParallel = conf.Server.MaxGoRoutineParallel
	}
	log.Info("Total Server CPU cores: %d | Total number of goroutines configured to run in parallel: %d", maxCPUCore, maxGoroutinesInParallel)

	runtime.GOMAXPROCS(maxGoroutinesInParallel)

	if globalApp.Config.Server.MaxGoRoutineParallel != maxCPUCore && globalApp.Config.Server.MaxGoRoutineParallel != 0 {
		log.Warn("For best performance, the CPU cores and GoRoutine should have the same value.")
	}

	// INFO
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	memAllocatedInMB := float64(mem.Alloc) / 1024 / 1024

	serverInfo := &app.Info{
		ServerVersion:           version,
		GinVersion:              gin.Version,
		GoVersion:               runtime.Version(),
		ServerStartTime:         time.Now(),
		CertificatePath:         certificate.Path,
		NumGoroutinesInParallel: runtime.GOMAXPROCS(0),
		MemStatsInMB:            memAllocatedInMB,
		NumCPU:                  runtime.NumCPU(),
	}

	// START GIN FRAMEWORK
	serverRouter := gin.Default()

	// VIRTUAL HOSTS
	virtualHosts, defaultSite := virtualhosts.Setup(serverRouter, globalApp.Config, globalApp.LogApp)

	// APPLY MIDDLEWARE
	serverRouter.Use(middlewares.LoggingMiddleware(globalApp.LogApp))
	serverRouter.Use(middlewares.SecureMiddleware(globalApp.LogApp, globalApp.Config.Server.Dev))
	serverRouter.Use(middlewares.RedirectOrAllowHostMiddleware(globalApp.LogApp, virtualHosts))

	// TODO estoy trabajando aqui para habilitar os CORS y permitir el F5 (envio de credenciales en las cookies)
	serverRouter.Use(middlewares.CorsMiddleware(globalApp.Config.Sites, globalApp.LogApp))
	// []string{"https://www.humanjuan.com", "https://humanjuan.com", "https://golyn.humanjuan.com", "https://portal.humanjuan.com"}

	// CREATE SERVER CACHE AND APPLY MORE MIDDLEWARE
	serverRouter.Use(middlewares.CacheMiddleware(globalApp.LogApp,
		cache.New(
			time.Duration(globalApp.Config.Cache.ExpirationTime)*time.Minute,
			time.Duration(globalApp.Config.Cache.CleanUpInterval)*time.Minute,
		)),
	)
	log.Info("The server cache has been configured with an expiration time of %v minutes and %v minutes "+
		"to clean up interval.", conf.Cache.ExpirationTime, conf.Cache.CleanUpInterval)

	routes.ConfigureRoutes(serverRouter, globalApp, serverInfo, mainDomain)

	// ADD CUSTOM NoRoute HANDLER
	serverRouter.NoRoute(func(c *gin.Context) {
		host := c.Request.Host
		path := c.Request.URL.Path

		log.Warn("NoRoute() | Request Not Found | Host: %s | Path: %s | Method: %s", host, path, c.Request.Method)

		if len(path) >= 4 && path[:4] == "/api" {
			c.IndentedJSON(http.StatusNotFound, gin.H{
				"message": utils.GetCodeMessage(http.StatusNotFound),
				"error":   "Resource not found",
			})
			c.Abort()
			return
		}

		vh, ok := virtualHosts[host]
		if ok {
			handlers.ServeErrorPage(c, log, http.StatusNotFound, "", vh.BasePath, defaultSite)
			return
		}
		handlers.ServeErrorPage(c, log, http.StatusNotFound, "", defaultSite, defaultSite)
	})

	// SET INITIAL SERVER PARAMETERS FOR SITES SERVER
	serverHTTPS, err := internal.SetupServerHTTPS(globalApp.Config, serverRouter, certificate)
	if err != nil {
		log.Error(err.Error())
		panic(err.Error())
	}
	log.Info("TLS server configured on port %d", conf.Server.Port)

	// START HTTP TO HTTPS REDIRECT
	serverHTTP, err := internal.SetupServerHTTP()
	if err != nil {
		log.Error(err.Error())
		panic(err.Error())
	}
	log.Info("Server HTTP to redirect it's Up on port 80")

	mode := "Release"
	if globalApp.Config.Server.Dev {
		mode = "Development"
	}

	var wg sync.WaitGroup

	// Ejecutar el servidor HTTPS
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("Starting HTTPS server on %s (%v mode)\n", serverHTTPS.Addr, mode)
		err := serverHTTPS.ListenAndServeTLS(certificate.Path, certificate.Key)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTPS Server Error: %v", err)
			os.Exit(1)
		}
	}()

	// Ejecutar el servidor HTTP
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("Starting HTTP server for redirect on %s\n", serverHTTP.Addr)
		err := serverHTTP.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP Server Error: %v", err)
			os.Exit(1)
		}
	}()

	// Manejo de apagado
	wg.Add(1)
	go func() {
		defer wg.Done()
		internal.CatchSignalDual(serverHTTPS, serverHTTP, globalApp.LogApp)
	}()

	// Esperar todas las gorutinas
	wg.Wait()
	log.Info("Server exited.")

}
