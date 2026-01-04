# ywyh PCE (spf)

Minimal example showing how to construct a `BGPUpdateMessage`, start
the `Spf` pipeline and read generated `SRv6Paths`.

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
    spf.GlobalLSDB = db

    s := spf.NewSpf(1, 1)
    s.Start()
    defer s.Stop()

    msg := spf.NewBGPUpdate(42)
    s.BgpUpdates <- msg

    select {
    case p := <-s.SrPaths:
        fmt.Printf("SRP ID=%d LSP len=%d\n", p.SRPID(), p.LSPLength())
    case <-time.After(time.Second):
        fmt.Println("timeout")
    }
}
```
<!--
README: ywyh

This repository contains a minimal proof-of-concept PCE/SPF pipeline
for experimenting with BGP update to SRv6 path conversions. See the
`spf` package for core types and helpers.
-->
