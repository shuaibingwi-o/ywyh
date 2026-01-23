# ywyh PCE (spf)

Minimal proof-of-concept PCE / SPF pipeline with PCEP server support.

## Usage Summary

- Create or load an `LSDB` and set `spf.GlobalLSDB` if desired.
- Create an `Spf` with `spf.NewSpf(inBuf, outBuf)` and call `Start()`.
- Send parsed `*bgp.BGPMessage` values directly into the `Spf` by
  writing to the `s.BgpUpdates` channel. The pipeline's internal
  processing loop will:
    1. apply the BGP update to the LSDB (`ApplyBGPUpdateToLSDB`),
    2. attempt a representative path calculation (`CalculatePath`),
    3. construct a `PCUpd` and emit it on `s.SrPaths` (only when the
     LSDB changed, or for synthetic test messages).

## Example

```go
package main

import (
    "fmt"
    "time"

    "ywyh/spf"
)

func main() {
    db := spf.NewLSDB()
    db.AddLink(&spf.Link{InfId: "lnk1"})
    db.AddLink(&spf.Link{InfId: "lnk2"})
    spf.GlobalLSDB = db

    s := spf.NewSpf(1000, 1000)
    s.Start()
    defer s.Stop()

    // create a synthetic BGP update with SRP identifier 42
    msg := spf.NewBGPUpdate(42)
    // send the parsed BGP message into the pipeline
    s.BgpUpdates <- msg

    select {
    case p := <-s.SrPaths:
        if p == nil {
            fmt.Println("received nil PCUpd")
            return
        }
        fmt.Printf("SRP ID=%d LSP length=%d\n", p.SRPID, p.LSPLen)
    case <-time.After(time.Second):
        fmt.Println("timeout waiting for PCUpd")
    }
}
```

See the `spf` package for details on `ApplyBGPUpdateToLSDB`, path
calculation and `PCUpd` packaging.

## PCE Server Example

For a complete PCEP server implementation, see `examples/pce_server.go`. It demonstrates:
- Listening for PCEP connections on port 4189.
- Handling PCEP Open, PCReq, and PCRep messages.
- Concurrent path computation using a worker pool.
- Integration with the SPF pipeline for PCUpd generation.

Build and run with:
```bash
go build ./examples/pce_server.go
./pce_server
```

## Quickstart: run PCE + IPv6 PCC + BGP speaker

This repository includes three runnable endpoints under `endpoints/`:
- `endpoints/pce_server/main.go` — mock PCE server (PCEP + SPF + unix socket listener)
- `endpoints/pcc_client/main.go` — scripted PCC client (use `--hold` to keep connection)
- `endpoints/bgp_speaker/main.go` — builds a BGP‑LS UPDATE and writes raw bytes to `/tmp/pce_bgp.sock`

Recommended sequence (use two terminals):

1) Start the PCE (clears sessions on restart):
```bash
pkill -f endpoints/pce_server/main.go || true
nohup go run endpoints/pce_server/main.go --sid 2001:db8::1 > /tmp/pce_server.log 2>&1 &
tail -f /tmp/pce_server.log
```

2) In a separate terminal start a single IPv6 PCC and keep it running
```bash
go run endpoints/pcc_client/main.go --addr [::1]:4189 --hold
```

3) Inject a BGP‑LS update (speaker):
```bash
go run endpoints/bgp_speaker/main.go --sid 2001:db8::200 --non-interactive --socket /tmp/pce_bgp.sock
```

What to look for
- `/tmp/pce_server.log`: lines like `PCUpd wire to <addr>: <hex>` and `Sent unsolicited PCUpd to <addr>...` indicate the PCE built and sent a PCUpd.
- PCC terminal: client prints incoming PCEP messages; you should see an incoming `PCUpd` after the speaker runs.

Notes
- The PCE chooses the earliest-connected active PCC and sends the unsolicited `PCUpd` only to that session (no broadcast).
- If the BGP parser rejects a raw message, the PCE will log the raw bytes and attempt a heuristic SID extraction to avoid losing updates during development.

