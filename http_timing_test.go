package blockcheck

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPResponseStartIsSeparateFromTransfer(t *testing.T) {
	for _, name := range []string{"response and transfer", "no response data"} {
		t.Run(name, func(t *testing.T) {
			client, peer := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
			if err := client.SetDeadline(time.Now().Add(ProbeBudget)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				defer peer.Close()
				req, err := http.ReadRequest(bufio.NewReader(peer))
				if err != nil || name == "no response data" {
					done <- err
					return
				}
				if req.Method != http.MethodGet || req.URL.Path != "/" {
					done <- fmt.Errorf("unexpected request: %s %s", req.Method, req.URL)
					return
				}
				time.Sleep(20 * time.Millisecond)
				if _, err = io.WriteString(peer, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"); err != nil {
					done <- err
					return
				}
				time.Sleep(35 * time.Millisecond)
				_, err = io.WriteString(peer, "data")
				done <- err
			}()
			row := Result{Cell: Cell{Probe: HTTPData}}
			started := time.Now()
			probeHTTP(&row, "fixture.example", client)
			elapsed := time.Since(started).Milliseconds()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if name == "no response data" {
				if row.Status != StreamClosed || row.HTTPResponseStartMS != nil {
					t.Fatalf("no response must not produce a timing: %+v", row)
				}
				return
			}
			if row.HTTPResponseStartMS == nil || *row.HTTPResponseStartMS < 20 ||
				elapsed-*row.HTTPResponseStartMS < 20 || row.BodyReadMS < 15 || row.BodyBytes != 4 ||
				row.Status != HTTPResponse || row.HTTPStatus != 200 {
				t.Fatalf("response and transfer were not observed separately: %+v (total %d ms)", row, elapsed)
			}
		})
	}
}
