package a

import (
	. "net"
	web "net/http"
	_ "net/http/httptest"
	"net/rpc"
)

// Serve listens in many ways; dialing out is allowed.
func Serve() {
	l, _ := Listen("tcp", ":8080")
	var lc ListenConfig
	_, _ = FileListener(nil)
	_ = web.Serve(l, nil)
	var s web.Server
	_ = web.ListenAndServeTLS(":443", "c", "k", nil)
	_, _ = Dial("udp", "192.0.2.53:53")
	_, _, _ = lc, s, rpc.ErrShutdown
}
