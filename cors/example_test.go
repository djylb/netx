package cors_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/djylb/netx/cors"
)

func ExampleCompile() {
	p, err := cors.Compile(cors.Policy{Origins: []string{"https://*.example.test"}, Methods: []string{http.MethodPut}})
	if err != nil {
		panic(err)
	}
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.test")
	req.Header.Set("Access-Control-Request-Method", http.MethodPut)
	route, local := cors.SelectPreflight(req, func(method string) (string, bool) { return method, p.LocalPreflight() })
	w := httptest.NewRecorder()
	if local {
		p.Preflight(w, req)
	}
	fmt.Println(route, w.Code, w.Header().Get("Access-Control-Allow-Origin"))
	// Output: PUT 204 https://app.example.test
}

func ExampleCompiled_ApplyResponse() {
	p, err := cors.Compile(cors.Policy{Origins: []string{"https://app.example.test"}, Credentials: true})
	if err != nil {
		panic(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example.test")
	res := &http.Response{StatusCode: http.StatusOK}
	p.ApplyResponse(res, req)
	fmt.Println(res.Header.Get("Access-Control-Allow-Credentials"), res.Header.Get("Vary"))
	// Output: true Origin
}
