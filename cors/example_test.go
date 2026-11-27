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

func ExampleAddPreflightVary() {
	p, err := cors.Compile(cors.Policy{OriginMode: cors.OriginReflect, Methods: []string{http.MethodPost}})
	if err != nil {
		panic(err)
	}
	routes := map[string]*cors.Compiled{http.MethodPost: p}
	handle := func(w http.ResponseWriter, r *http.Request, admitted bool) {
		policy, local := cors.SelectPreflight(r, func(method string) (*cors.Compiled, bool) {
			c := routes[method]
			return c, c.LocalPreflight()
		})
		if local {
			cors.AddPreflightVary(w.Header())
		}
		if !admitted {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if local {
			policy.Preflight(w, r)
		}
	}
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.test")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	denied := httptest.NewRecorder()
	handle(denied, req, false)
	granted := httptest.NewRecorder()
	handle(granted, req, true)
	fmt.Println(denied.Code, denied.Header().Get("Vary"))
	fmt.Println(granted.Code, granted.Header().Get("Access-Control-Allow-Origin"))
	// Output:
	// 403 Origin, Access-Control-Request-Method, Access-Control-Request-Headers
	// 204 https://app.example.test
}
