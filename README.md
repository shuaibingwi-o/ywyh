# ywyh PCE (spf)

Minimal proof-of-concept PCE / SPF pipeline.

Usage summary

- Create or load an `LSDB` and set `spf.GlobalLSDB` if desired.
- Create an `Spf` with `spf.NewSpf(inBuf, outBuf)` and call `Start()`.
- Send parsed `*bgp.BGPMessage` values directly into the `Spf` by
  writing to the `s.BgpUpdates` channel. The pipeline's internal
  processing loop will:
    1. apply the BGP update to the LSDB (`ApplyBGPUpdateToLSDB`),
    2. attempt a representative path calculation (`CalculatePath`),
    3. construct a `PCUpd` and emit it on `s.SrPaths` (only when the
     LSDB changed, or for synthetic test messages).

Example

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

    s := spf.NewSpf(1, 1)
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
