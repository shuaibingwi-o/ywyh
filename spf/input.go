package spf

import (
	"fmt"
	"hash/fnv"
	"reflect"
	"strings"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// applyBGPUpdateToLSDB updates the GlobalLSDB based on the provided
// *bgp.BGPMessage. It inspects the message for NLRI/path-attributes and
// materializes deterministic Node and Link entries so the SPF pipeline
// can compute paths. Synthetic test messages registered in bgpSrp are
// ignored to avoid interfering with tests.
// applyBGPUpdateToLSDB applies the provided BGP message to the
// GlobalLSDB. It returns true if the LSDB was modified.
func ApplyBGPUpdateToLSDB(m *bgp.BGPMessage) bool {
	if m == nil {
		return false
	}

	bgpSrpMu.Lock()
	_, synthetic := bgpSrp[m]
	bgpSrpMu.Unlock()
	if synthetic {
		return false
	}

	// Collect NLRI-like strings by reflecting through the message.
	var nlriStrs []string
	target := reflect.TypeOf(bgp.PathNLRI{})

	var walk func(reflect.Value)
	walk = func(rv reflect.Value) {
		if !rv.IsValid() {
			return
		}
		switch rv.Kind() {
		case reflect.Ptr, reflect.Interface:
			if !rv.IsNil() {
				walk(rv.Elem())
			}
		case reflect.Struct:
			for i := 0; i < rv.NumField(); i++ {
				fv := rv.Field(i)
				if fv.IsValid() && fv.CanInterface() {
					if s := fmt.Sprint(fv.Interface()); len(s) > 0 {
						if containsSlash(s) || looksLikeSRInfo(s) {
							nlriStrs = append(nlriStrs, s)
						}
					}
				}
				walk(fv)
			}
		case reflect.Slice, reflect.Array:
			et := rv.Type().Elem()
			if et == target {
				for i := 0; i < rv.Len(); i++ {
					item := rv.Index(i)
					if item.Kind() == reflect.Struct {
						f := item.FieldByName("NLRI")
						if f.IsValid() {
							nlriStrs = append(nlriStrs, fmt.Sprint(f.Interface()))
						}
					}
				}
			} else {
				for i := 0; i < rv.Len(); i++ {
					item := rv.Index(i)
					if item.IsValid() && item.CanInterface() {
						if s := fmt.Sprint(item.Interface()); containsSlash(s) || looksLikeSRInfo(s) {
							nlriStrs = append(nlriStrs, s)
						}
					}
					walk(item)
				}
			}
		}
	}

	rv := reflect.ValueOf(m)
	walk(rv)

	if len(nlriStrs) == 0 {
		return false
	}

	var prevID uint32
	for idx, s := range nlriStrs {
		h := fnv.New32a()
		h.Write([]byte(s))
		id := h.Sum32()
		node := &Node{RouterId: id, Locator: s}
		GlobalLSDB.AddNode(node)
		if idx > 0 {
			link := &Link{InfId: fmt.Sprintf("nlri-link-%d-%d", prevID, id), SrcNode: prevID, DstNode: id, Status: true}
			GlobalLSDB.AddLink(link)
		}
		prevID = id
	}
	return true
}

func containsSlash(s string) bool { return strings.Contains(s, "/") }

func looksLikeSRInfo(s string) bool {
	ls := strings.ToLower(s)
	return strings.Contains(ls, "sr") || strings.Contains(ls, "sid") || strings.Contains(ls, "segment") || strings.Contains(ls, "srv6")
}
