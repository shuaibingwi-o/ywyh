package spf

import (
	"sync"
)

// LSDB placeholder.

type Node struct {
	RouterId uint32 `json:"routerId"`
	Msd      uint8  `json:"msd"`
	AsNum    uint32 `json:"asNum"`
	Locator  string `json:"locator"`
}
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

type LSDBManager interface {
	GetNode(id uint32) (*Node, bool)
	GetLink(id string) (*Link, bool)
}

func (db *LSDB) GetNode(id uint32) (*Node, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	node, exists := db.Nodes[id]
	return node, exists
}

func (db *LSDB) AddNode(node *Node) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.Nodes[node.RouterId] = node
}

func (db *LSDB) GetLink(id string) (*Link, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	link, exists := db.Links[id]
	return link, exists
}
func (db *LSDB) AddLink(link *Link) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.Links[link.InfId] = link
}

func NewLSDB() *LSDB {
	return &LSDB{
		Nodes: make(map[uint32]*Node),
		Links: make(map[string]*Link),
	}
}

var GlobalLSDB = NewLSDB()

func GetGlobalLSDB() *LSDB {
	return GlobalLSDB
}

func SaveLSDB(db *LSDB) {

	// Persist LSDB to `lsdb.json` in the current working directory.
	_ = SaveJSON("lsdb.json", db)
}
func LoadLSDB() *LSDB {
	db := NewLSDB()
	if err := LoadJSON("lsdb.json", db); err != nil {
		return db
	}
	return db
}
