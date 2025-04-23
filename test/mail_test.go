package test

import (
	"crypto/tls"
	"net/smtp"
	"testing"
)

func TestSendEmail(t *testing.T) {
	smtpHost := "<SMTP_HOST>"
	smtpPort := "<PORT>"
	from := "<FROM>"
	password := "<PASSWORD>"

	to := []string{"example@correo.com"}
	subject := "Cafest ABC1234"
	body := "This is a test email from Golyn Server"

	message := []byte("To: " + to[0] + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	auth := smtp.PlainAuth("", from, password, smtpHost)
	tlsConfig := &tls.Config{
		ServerName:         smtpHost,
		InsecureSkipVerify: false,
	}

	t.Run("send_email_ssl", func(t *testing.T) {
		client, err := smtp.Dial(smtpHost + ":" + smtpPort)
		if err != nil {
			t.Fatalf("Error connecting to server: %v", err)
		}
		defer client.Close()

		if err = client.StartTLS(tlsConfig); err != nil {
			t.Fatalf("Error starting TLS: %v", err)
		}

		if err = client.Auth(auth); err != nil {
			t.Fatalf("Authentication error: %v", err)
		}

		if err = client.Mail(from); err != nil {
			t.Fatalf("Error configuring sender: %v", err)
		}

		if err = client.Rcpt(to[0]); err != nil {
			t.Fatalf("Error configuring recipient: %v", err)
		}

		w, err := client.Data()
		if err != nil {
			t.Fatalf("Error getting writer: %v", err)
		}

		_, err = w.Write(message)
		if err != nil {
			t.Fatalf("Error writing message: %v", err)
		}

		err = w.Close()
		if err != nil {
			t.Fatalf("Error closing writer: %v", err)
		}

		err = client.Quit()
		if err != nil {
			t.Fatalf("Error closing connection: %v", err)
		}

		t.Log("Email sent successfully")
	})
}
