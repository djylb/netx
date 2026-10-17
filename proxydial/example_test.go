package proxydial_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/djylb/netx/proxydial"
)

func ExampleFromURL() {
	u, err := url.Parse("socks5://user:secret@proxy.example:1080")
	if err != nil {
		log.Fatal(err)
	}
	d, err := proxydial.FromURL(u, &net.Dialer{Timeout: 10 * time.Second}, nil)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		log.Println(err)
		return
	}
	defer func() { _ = conn.Close() }()
}

func ExampleParseNoProxy() {
	np := proxydial.ParseNoProxy("localhost, .corp.example, 10.0.0.0/8, internal:8080")
	for _, target := range []string{"localhost:5432", "db.corp.example:5432", "corp.example:443", "10.1.2.3:22", "internal:80", "example.com:443"} {
		fmt.Println(target, np.Match(target))
	}
	// Output:
	// localhost:5432 true
	// db.corp.example:5432 true
	// corp.example:443 false
	// 10.1.2.3:22 true
	// internal:80 false
	// example.com:443 false
}
