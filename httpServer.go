package main

import (
	"fmt"
    "log"
    "io"
    "context"
    "net/http"
    "sync"
    "time"
)

type handlerObj struct {
	dbg bool
	ch chan struct{}
}

func (h *handlerObj) handler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("request URI: %s\n", r.RequestURI)
	if r.RequestURI == "/hello" {
		fmt.Println("received hello!")
		io.WriteString(w, "hello world\n")
		h.ch <- struct{}{}
		return
	}
	io.WriteString(w, "not hello world\n")
}


func (h *handlerObj) startHttpServer(wg *sync.WaitGroup) *http.Server {
    srv := &http.Server{Addr: ":80"}

    http.HandleFunc("/", h.handler)

    go func() {
        defer wg.Done() // let main know we are done cleaning up

        // always returns error. ErrServerClosed on graceful close
        if err := srv.ListenAndServe(); err != http.ErrServerClosed {
            // unexpected error. port in use?
            log.Fatalf("ListenAndServe(): %v", err)
        }
    }()

    // returning reference so caller can call Shutdown()
    return srv
}

func main() {
    log.Printf("main: starting HTTP server")

    httpServerExitDone := &sync.WaitGroup{}

    httpServerExitDone.Add(1)

	h := new(handlerObj)
	h.ch = make (chan struct{})

    log.Printf("main: starting server")
    srv := h.startHttpServer(httpServerExitDone)

	select {
	case <-h.ch:
	case <-time.After(20*time.Second):
	}
//    time.Sleep(30 * time.Second)

    log.Printf("main: stopping HTTP server")

    // now close the server gracefully ("shutdown")
    // timeout could be given with a proper context
    // (in real world you shouldn't use TODO()).
    if err := srv.Shutdown(context.TODO()); err != nil {
        panic(err) // failure/timeout shutting down the server gracefully
    }

    // wait for goroutine started in startHttpServer() to stop
    // NOTE: as @sander points out in comments, this might be unnecessary.
    httpServerExitDone.Wait()

    log.Printf("main: done. exiting")
}
