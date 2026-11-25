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
	for _, name := range []string{"single body read", "split body", "no response data"} {
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
				if name == "split body" {
					if _, err = io.WriteString(peer, "da"); err != nil {
						done <- err
						return
					}
					time.Sleep(35 * time.Millisecond)
					_, err = io.WriteString(peer, "ta")
				} else {
					_, err = io.WriteString(peer, "data")
				}
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
				if row.Status != StreamClosed || row.HTTPResponseStartMS != nil || row.BodyReadMS != nil || row.BodyMaxGapMS != nil {
					t.Fatalf("no response must not produce a timing: %+v", row)
				}
				return
			}
			if row.HTTPResponseStartMS == nil || *row.HTTPResponseStartMS < 20 ||
				elapsed-*row.HTTPResponseStartMS < 20 || row.BodyReadMS == nil || *row.BodyReadMS < 15 || row.BodyBytes != 4 ||
				row.Status != HTTPResponse || row.HTTPStatus != 200 {
				t.Fatalf("response and transfer were not observed separately: %+v (total %d ms)", row, elapsed)
			}
			if name == "split body" {
				if row.BodyMaxGapMS == nil || *row.BodyMaxGapMS < 25 {
					t.Fatalf("missing measured interval: %+v", row)
				}
			} else if row.BodyMaxGapMS != nil {
				t.Fatalf("one body read cannot produce an interval: %+v", row)
			}
		})
	}
}

func TestTransferPauseInterpretationDoesNotReplaceInterruption(t *testing.T) {
	timing := transferTiming{}
	start := time.Unix(1, 0)
	timing.observe(start)
	if timing.max != nil {
		t.Fatal("recorded an interval on the first read")
	}
	timing.observe(start.Add(500 * time.Microsecond))
	if timing.max == nil || *timing.max != 0 {
		t.Fatal("a measured zero interval was lost")
	}
	row := Result{Stage: StageTransfer, Status: HTTPResponse, BodyMaxGapMS: timing.max}
	if observation := interpretProbe(row); observation != nil {
		t.Fatalf("ordinary interval marked as a pause: %+v", observation)
	}
	timing.observe(start.Add(2501 * time.Millisecond))
	timing.observe(start.Add(2600 * time.Millisecond))
	if *row.BodyMaxGapMS != 2500 {
		t.Fatalf("longest interval changed: %dms", *row.BodyMaxGapMS)
	}
	if observation := interpretProbe(row); observation == nil || observation.Code != "transfer_pause_observed" || observation.Confidence != "observed" || len(observation.Alternatives) < 2 {
		t.Fatalf("missing pause or alternatives: %+v", observation)
	}
	row.Status = Timeout
	if observation := interpretProbe(row); observation == nil || observation.Code != "transfer_interrupted" {
		t.Fatalf("pause masked interruption: %+v", observation)
	}
}
