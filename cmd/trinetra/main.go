package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata"
	"trinetra/internal/app"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func main() {
	addr := flag.String("addr", env("LISTEN_ADDR", "127.0.0.1:5173"), "HTTP listen address")
	data := flag.String("data", env("DATA_DIR", "data"), "Data directory")
	static := flag.String("static", env("STATIC_DIR", "dist"), "React build directory")
	flag.Parse()
	a, e := app.New(app.Config{DataDir: *data, StaticDir: *static, Origin: os.Getenv("APP_ORIGIN"), TimeZone: env("APP_TIMEZONE", "America/New_York"), SecureCookie: os.Getenv("COOKIE_SECURE") == "1"})
	if e != nil {
		log.Fatal(e)
	}
	defer a.Close()
	server := &http.Server{Addr: *addr, Handler: a, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	fmt.Printf("InfraLedger — Go REST API + React / TypeScript\nhttp://%s\nData: %s\n", *addr, *data)
	if e = server.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
