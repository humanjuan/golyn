package handlers

import (
	"crypto/tls"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/humanjuan/golyn/config/loaders"
	"github.com/humanjuan/golyn/globals"
	"github.com/humanjuan/golyn/internal/security"
	"github.com/humanjuan/golyn/internal/utils"
	"net/http"
	gosmtp "net/smtp"
	"strings"
	"time"
)

type SendMailRequest struct {
	Name    string `form:"name" binding:"required,max=100"`
	Email   string `form:"email" binding:"required,email"`
	Message string `form:"message" binding:"required,max=1000"`
}

func SendmailHandler() gin.HandlerFunc {
	log := globals.GetAppLogger()
	var err error
	log.Debug("SendmailHandler()")
	return func(c *gin.Context) {
		host := strings.Split(c.Request.Host, ":")[0]

		var smtp loaders.SMTP
		if cfg, exists := c.Get("site_config"); exists {
			if siteCfg, ok := cfg.(loaders.SiteConfig); ok {
				smtp = siteCfg.SMTP
			}
		}

		if smtp.Host == "" {
			// Fallback to VirtualHosts
			if site, ok := globals.VirtualHosts[host]; ok {
				smtp = site.SMTP
			}
		}

		if smtp.Host == "" {
			log.Warn("SendmailHandler() | Access denied or SMTP not configured | Host: %s | URL: %s", host, c.Request.URL)
			err = fmt.Errorf("access denied or SMTP not configured for host %s", host)
			c.Error(utils.NewHTTPError(http.StatusForbidden, err.Error()))
			return
		}

		var request SendMailRequest
		if err := c.ShouldBind(&request); err != nil {
			log.Error("SendmailHandler() | Invalid or unexpectedly formatted JSON provided in request body. %s", err.Error())
			log.Sync()
			err = fmt.Errorf("invalid or unexpectedly formatted JSON provided in request body")
			c.Error(utils.NewHTTPError(http.StatusBadRequest, err.Error()))
			return
		}

		// message sanitization
		request.Name = utils.SanitizeInput(request.Name)
		request.Email = utils.SanitizeInput(request.Email)
		request.Message = utils.SanitizeInput(request.Message)
		if request.Name == "" || request.Email == "" || request.Message == "" {
			log.Error("SendmailHandler() | Invalid input after sanitization.")
			log.Sync()
			err = fmt.Errorf("invalid input after sanitization")
			c.Error(utils.NewHTTPError(http.StatusBadRequest, err.Error()))
			return
		}

		smtpHost := smtp.Host
		smtpPort := fmt.Sprintf("%d", smtp.Port)
		addr := smtpHost + ":" + smtpPort
		passwordDecrypted, err := security.DecryptPassword(smtp.Password)

		from := smtp.Username
		to := smtp.Username
		subject := fmt.Sprintf("Message from %s", request.Name)
		body := fmt.Sprintf("Name: %s\nEmail: %s\nMessage: %s", request.Name, request.Email, request.Message)
		message := []byte(fmt.Sprintf("To: %s\r\n"+
			"From: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"X-Mailer: GolandSMTP\r\n"+
			"Message-ID: <%d.%s>\r\n"+
			"\r\n"+
			"%s\r\n",
			to, from, subject,
			time.Now().UnixNano(), smtpHost,
			body))

		tlsConfig := &tls.Config{
			ServerName:         smtpHost,
			InsecureSkipVerify: false,
		}

		log.Debug("SendmailHandler() | Attempting to send email"+
			" | SMTP Host: %s"+
			" | SMTP Port: %s"+
			" | From: %s"+
			" | To: %s"+
			" | Message-ID: <%d.%s>"+
			" | TLS Config: %+v",
			smtpHost, smtpPort, from, to,
			time.Now().UnixNano(), smtpHost,
			tlsConfig)

		if err != nil {
			log.Error("SendmailHandler() | Error decrypting password: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("error decrypting password")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}
		auth := gosmtp.PlainAuth("", from, passwordDecrypted, smtpHost)

		client, err := gosmtp.Dial(addr)
		if err != nil {
			log.Error("SendmailHandler() | Failed to connect to SMTP: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("failed to connect to SMTP")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}
		defer client.Close()

		if err := client.StartTLS(tlsConfig); err != nil {
			log.Error("SendmailHandler() | Failed to start TLS: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("failed to start TLS")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		if err := client.Auth(auth); err != nil {
			log.Error("SendmailHandler() | Failed to authenticate: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("failed to authenticate")
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		if err := client.Mail(from); err != nil {
			log.Error("SendmailHandler() | Failed to set sender: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("failed to set sender: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		if err := client.Rcpt(to); err != nil {
			log.Error("SendmailHandler() | Failed to set recipient: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("failed to set recipient: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		w, err := client.Data()
		if err != nil {
			log.Error("SendmailHandler() | Failed to send message: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("failed to send message: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		_, err = w.Write(message)
		if err != nil {
			log.Error("SendmailHandler() | Failed to write message: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("failed to write message: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		if err := w.Close(); err != nil {
			log.Error("SendmailHandler() | Failed to close connection: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("failed to close connection: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		if err := client.Quit(); err != nil {
			log.Error("SendmailHandler() | Failed to quit connection: %v", err.Error())
			log.Sync()
			err = fmt.Errorf("failed to quit connection: %v", err)
			c.Error(utils.NewHTTPError(http.StatusInternalServerError, err.Error()))
			return
		}

		log.Info("SendmailHandler() | Message sent successfully | from: %s | to: %s", from, to)
		c.JSON(http.StatusOK, utils.APIResponse{
			Success: true,
			Message: "Message sent successfully",
		})
	}
}
