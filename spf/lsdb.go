// Package spf contains a simple Link State Database (LSDB) representation
// used by the SPF pipeline. The LSDB is intentionally minimal for
// demonstration and testing purposes.
package spf

import (
	"sync"
)

// LSDB placeholder.

// Node represents a network node stored in the LSDB.
type Node struct {
	RouterId uint32 `json:"routerId"`
	Msd      uint8  `json:"msd"`
	AsNum    uint32 `json:"asNum"`
	Locator  string `json:"locator"`
}

// Link represents a network adjacency stored in the LSDB.
type Link struct {
	InfId  string  `json:"infId"`
	Loss   float32 `json:"loss"`
	Delay  float32 `json:"delay"`
	Status bool    `json:"status"`
	Sid    string  `json:"sid"`
}

// LSDB数据结构
type LSDB struct {
	mu    sync.RWMutex
	Nodes map[uint32]*Node `json:"nodes"` // 节点ID到节点对象的映射
	Links map[string]*Link `json:"links"` // 链路ID到链路对象的映射
}

// LSDBManager defines read-only access to an LSDB.
type LSDBManager interface {
	GetNode(id uint32) (*Node, bool)
	GetLink(id string) (*Link, bool)
}

// GetNode returns the Node with the given id and whether it exists.
func (db *LSDB) GetNode(id uint32) (*Node, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	node, exists := db.Nodes[id]
	return node, exists
}

// AddNode adds or updates a Node in the LSDB.
func (db *LSDB) AddNode(node *Node) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.Nodes[node.RouterId] = node
}

// GetLink returns the Link with the given id and whether it exists.
func (db *LSDB) GetLink(id string) (*Link, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	link, exists := db.Links[id]
	return link, exists
}

// AddLink adds or updates a Link in the LSDB.
func (db *LSDB) AddLink(link *Link) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.Links[link.InfId] = link
}

// NewLSDB constructs and returns an empty LSDB.
func NewLSDB() *LSDB {
	return &LSDB{
		Nodes: make(map[uint32]*Node),
		Links: make(map[string]*Link),
	}
}

var GlobalLSDB = NewLSDB()

// GetGlobalLSDB returns the singleton GlobalLSDB instance.
func GetGlobalLSDB() *LSDB {
	return GlobalLSDB
}

// SaveLSDB persists the provided LSDB to a JSON file (`lsdb.json`).
func SaveLSDB(db *LSDB) {
	// Persist LSDB to `lsdb.json` in the current working directory.
	_ = SaveJSON("lsdb.json", db)
}

// LoadLSDB loads LSDB data from `lsdb.json` into a new LSDB and returns it.
// On error it returns an empty LSDB.
func LoadLSDB() *LSDB {
	db := NewLSDB()
	if err := LoadJSON("lsdb.json", db); err != nil {
		return db
	}
	return db
}
