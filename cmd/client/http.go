package main

import (
	"log"
	"net/http"
	"time"
)

func logging(tag string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		q := ""
		if r.URL.RawQuery != "" {
			q = "?" + r.URL.RawQuery
		}
		log.Printf("[%s] %s %s%s (%s)", tag, r.Method, r.URL.Path, q, time.Since(start).Round(time.Microsecond))
	})
}
