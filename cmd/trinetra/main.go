package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"
	"trinetra/internal/app"
)

// version is set at build time: -ldflags "-X main.version=<commit>".
var version = "dev"

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loopbackOnly(addr string) bool {
	host, _, e := net.SplitHostPort(addr)
	if e != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, e := netip.ParseAddr(host)
	return e == nil && ip.IsLoopback()
}

func splitList(v string) []string {
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func main() {
	addr := flag.String("addr", env("LISTEN_ADDR", "127.0.0.1:5173"), "Listen address")
	data := flag.String("data", env("DATA_DIR", "data"), "Data directory")
	static := flag.String("static", env("STATIC_DIR", "dist"), "React build directory")
	certFile := flag.String("tls-cert", os.Getenv("TLS_CERT_FILE"), "TLS certificate (PEM) for HTTPS")
	keyFile := flag.String("tls-key", os.Getenv("TLS_KEY_FILE"), "TLS private key (PEM) for HTTPS")
	exportKey := flag.Bool("export-vault-key", false, "Print the vault recovery key and exit")
	rotateKey := flag.Bool("rotate-vault-key", false, "Re-encrypt all secrets with a new vault key (server must be stopped) and exit")
	showVersion := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *rotateKey {
		if e := app.RotateVaultKey(*data); e != nil {
			log.Fatal(e)
		}
		fmt.Println("Vault key rotated. Export a new recovery key now with -export-vault-key; the previous recovery key no longer works.")
		return
	}
	if *exportKey {
		key, e := app.ExportVaultKey(*data)
		if e != nil {
			log.Fatal(e)
		}
		fmt.Println("Vault recovery key. Store it offline (for example in a sealed envelope or a separate password manager).")
		fmt.Println("To restore on another computer, start InfraLedger with the environment variable VAULT_KEY set to this value.")
		fmt.Println(key)
		return
	}
	useTLS := *certFile != "" || *keyFile != ""
	if useTLS && (*certFile == "" || *keyFile == "") {
		log.Fatal("Set both -tls-cert and -tls-key")
	}
	behindHTTPSProxy := os.Getenv("COOKIE_SECURE") == "1"
	if !useTLS && !behindHTTPSProxy && !loopbackOnly(*addr) && os.Getenv("ALLOW_INSECURE_HTTP") != "1" {
		log.Fatalf("Refusing to serve plain HTTP on %s: passwords and vault secrets would cross the network unencrypted.\n"+
			"Use -tls-cert/-tls-key, or put an HTTPS reverse proxy in front and set COOKIE_SECURE=1, or keep the default 127.0.0.1 address.\n"+
			"(Set ALLOW_INSECURE_HTTP=1 only on an isolated test network.)", *addr)
	}
	a, e := app.New(app.Config{
		DataDir: *data, StaticDir: *static, Origin: os.Getenv("APP_ORIGIN"), TimeZone: env("APP_TIMEZONE", "America/New_York"),
		SecureCookie: useTLS || behindHTTPSProxy, TrustedProxy: os.Getenv("TRUSTED_PROXY"),
		AllowedHosts: splitList(os.Getenv("ALLOWED_HOSTS")), Version: version,
	})
	if e != nil {
		log.Fatal(e)
	}
	defer a.Close()
	server := &http.Server{Addr: *addr, Handler: a, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	fmt.Printf("InfraLedger %s\n%s://%s\nData: %s\n", version, scheme, *addr, *data)
	if useTLS {
		e = server.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		e = server.ListenAndServe()
	}
	if e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
