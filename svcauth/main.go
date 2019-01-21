package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"net/http"

	"github.com/gorilla/handlers"
)

var (
	//AppName is the name of this web app
	AppName = "auth"
)

func main() {
	//create a context
	ctx := context.Background()

	//create the auth service manager
	rn, err := NewSvMgr(ctx, AppName)

	if err != nil {
		log.Printf("failed at NewSvMgr:%v", err)
	}

	//create a logged router
	loggedRouter := handlers.CombinedLoggingHandler(os.Stdout, rn.Mx)

	//port selection (required by 2nd gen app engine)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	//create the server (based on recommended gorilla mux settings)
	sv := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      loggedRouter,
	}

	//serve
	if err := sv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
