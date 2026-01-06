// Package spf contains a simple Link State Database (LSDB) representation
// used by the SPF pipeline. The LSDB is intentionally minimal for
// demonstration and testing purposes.
package spf

import (
	"container/heap"
	"errors"
	"math"
	"os"
	"sync"
)

// LSDB placeholder.

// Node represents a network node stored in the LSDB.
type Node struct {
	RouterId uint32 `json:"routerId"`
	Msd      uint8  `json:"msd"`
	AsNum    uint32 `json:"asNum"`
	Locator  string `json:"locator"`
	// Neighbor information
	Neighbors map[uint32]string `json:"neighbors,omitempty"` // neighbor node ID -> link ID
	// SRv6 SIDs discovered for this node (if any)
	SRv6SIDs []string `json:"srv6sids,omitempty"`
}

// Link represents a network adjacency stored in the LSDB.
type Link struct {
	InfId     string  `json:"infId"`
	SrcNode   uint32  `json:"srcNode,omitempty"`   // source node ID
	DstNode   uint32  `json:"dstNode,omitempty"`   // destination node ID
	Loss      float32 `json:"loss"`                // packet loss rate (0-1)
	Delay     float32 `json:"delay"`               // delay (ms)
	Status    bool    `json:"status"`              // link status
	Sid       string  `json:"sid"`                 // Segment ID
	Bandwidth float32 `json:"bandwidth,omitempty"` // bandwidth (optional)
}

// LSDB data structure
type LSDB struct {
	mu    sync.RWMutex
	Nodes map[uint32]*Node `json:"nodes"` // mapping from node ID to Node
	Links map[string]*Link `json:"links"` // mapping from link ID to Link
	// Topology relationships
	Topology map[uint32]map[uint32]string `json:"topology,omitempty"` // src node -> dst node -> link ID
}

// LSDBManager defines read-only access to an LSDB.
type LSDBManager interface {
	GetNode(id uint32) (*Node, bool)
	GetLink(id string) (*Link, bool)
	CalculatePath(src, dst uint32, metricType MetricType) (*PathResult, error)
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

	// update topology
	if db.Topology == nil {
		db.Topology = make(map[uint32]map[uint32]string)
	}
	if db.Topology[link.SrcNode] == nil {
		db.Topology[link.SrcNode] = make(map[uint32]string)
	}
	db.Topology[link.SrcNode][link.DstNode] = link.InfId

	// update neighbor information for the source node
	if srcNode, exists := db.Nodes[link.SrcNode]; exists {
		if srcNode.Neighbors == nil {
			srcNode.Neighbors = make(map[uint32]string)
		}
		srcNode.Neighbors[link.DstNode] = link.InfId
	}

	// if the link is bidirectional, also add reverse topology
	if link.Status {
		if db.Topology[link.DstNode] == nil {
			db.Topology[link.DstNode] = make(map[uint32]string)
		}
		db.Topology[link.DstNode][link.SrcNode] = link.InfId

		if dstNode, exists := db.Nodes[link.DstNode]; exists {
			if dstNode.Neighbors == nil {
				dstNode.Neighbors = make(map[uint32]string)
			}
			dstNode.Neighbors[link.SrcNode] = link.InfId
		}
	}
}

// RemoveNode removes a node and its related links
func (db *LSDB) RemoveNode(nodeID uint32) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// remove the node
	delete(db.Nodes, nodeID)

	// remove all links in the topology related to that node
	for srcNodeID, targets := range db.Topology {
		for dstNodeID := range targets {
			if srcNodeID == nodeID || dstNodeID == nodeID {
				delete(targets, dstNodeID)
			}
		}
		if len(targets) == 0 {
			delete(db.Topology, srcNodeID)
		}
	}

	// remove this node from other nodes' neighbor lists
	for _, node := range db.Nodes {
		delete(node.Neighbors, nodeID)
	}
}

// RemoveLink removes a link
func (db *LSDB) RemoveLink(linkID string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	link, exists := db.Links[linkID]
	if !exists {
		return
	}

	// remove the link
	delete(db.Links, linkID)

	// update topology
	if targets, exists := db.Topology[link.SrcNode]; exists {
		delete(targets, link.DstNode)
		if len(targets) == 0 {
			delete(db.Topology, link.SrcNode)
		}
	}

	// if the link is bidirectional, also remove the reverse topology
	if link.Status {
		if targets, exists := db.Topology[link.DstNode]; exists {
			delete(targets, link.SrcNode)
			if len(targets) == 0 {
				delete(db.Topology, link.DstNode)
			}
		}
	}

	// update neighbor information for affected nodes
	if srcNode, exists := db.Nodes[link.SrcNode]; exists {
		delete(srcNode.Neighbors, link.DstNode)
	}
	if dstNode, exists := db.Nodes[link.DstNode]; exists {
		delete(dstNode.Neighbors, link.SrcNode)
	}
}

// NewLSDB constructs and returns an empty LSDB.
func NewLSDB() *LSDB {
	return &LSDB{
		Nodes:    make(map[uint32]*Node),
		Links:    make(map[string]*Link),
		Topology: make(map[uint32]map[uint32]string),
	}
}

var GlobalLSDB = NewLSDB()

// GetGlobalLSDB returns the singleton GlobalLSDB instance.
func GetGlobalLSDB() *LSDB {
	return GlobalLSDB
}

// SaveLSDB persists the provided LSDB to a JSON file (`lsdb.json`).
func SaveLSDB(db *LSDB) {
	// Persist LSDB to `config/lsdb.json` in the current working directory.
	if err := SaveJSON("config/lsdb.json", db); err != nil {
		// optional: add logging
		// log.Printf("Failed to save LSDB: %v", err)
	}
}

// LoadLSDB loads LSDB data from `lsdb.json` into a new LSDB and returns it.
// On error it returns an empty LSDB.
func LoadLSDB() *LSDB {
	db := NewLSDB()
	if err := LoadJSON("config/lsdb.json", db); err != nil {
		return db
	}
	return db
}

// LoadOrCreateLSDB loads LSDB from file; if file does not exist returns a new LSDB
func LoadOrCreateLSDB(filename string) *LSDB {
	db := NewLSDB()
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// file does not exist, return empty LSDB
		return db
	}

	if err := LoadJSON(filename, db); err != nil {
		// failed to load, return empty LSDB
		return NewLSDB()
	}

	return db
}

// ==================== Dijkstra algorithm implementation ====================

// MetricType defines metric types used for path calculation
type MetricType int

const (
	MetricDelay     MetricType = iota // delay-based
	MetricLoss                        // loss-based
	MetricComposite                   // composite metric (delay + loss)
	MetricBandwidth                   // bandwidth-based (cost inversely proportional to bandwidth)
)

// PathNode used by the Dijkstra priority queue
type PathNode struct {
	NodeID   uint32
	Distance float64
	Index    int // index in the heap
}

// PriorityQueue implements a min-priority queue
type PriorityQueue []*PathNode

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	return pq[i].Distance < pq[j].Distance
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}

func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	node := x.(*PathNode)
	node.Index = n
	*pq = append(*pq, node)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	node := old[n-1]
	node.Index = -1
	*pq = old[0 : n-1]
	return node
}

// PathResult stores results of path computation
type PathResult struct {
	Path        []uint32   `json:"path"`        // node path
	Links       []string   `json:"links"`       // link ID path
	TotalDelay  float64    `json:"totalDelay"`  // total delay (ms)
	TotalLoss   float64    `json:"totalLoss"`   // total loss (composite)
	TotalCost   float64    `json:"totalCost"`   // total cost (per metric)
	Metric      MetricType `json:"metric"`      // metric used
	Description string     `json:"description"` // path description
}

// calculateLinkCost computes the cost of a link for a given metric
func calculateLinkCost(link *Link, metric MetricType) float64 {
	switch metric {
	case MetricDelay:
		return float64(link.Delay)
	case MetricLoss:
		// convert loss rate to cost (higher loss -> higher cost)
		if link.Loss <= 0 {
			return 0.1 // minimum cost
		}
		return float64(link.Loss * 100) // scaled to match delay units
	case MetricComposite:
		// composite metric: delay * (1 + loss penalty)
		// higher loss increases penalty
		lossPenalty := 1.0 + float64(link.Loss)*50.0
		return float64(link.Delay) * lossPenalty
	case MetricBandwidth:
		// bandwidth-based: higher bandwidth -> lower cost
		if link.Bandwidth <= 0 {
			return math.Inf(1) // invalid bandwidth
		}
		// use 1/bandwidth as cost
		return 1000.0 / float64(link.Bandwidth) // assume Mbps unit
	default:
		return float64(link.Delay)
	}
}

// GetMetricDescription returns a human-readable description for a metric type
func GetMetricDescription(metric MetricType) string {
	switch metric {
	case MetricDelay:
		return "Delay-based shortest path"
	case MetricLoss:
		return "Loss-based shortest path"
	case MetricComposite:
		return "Composite (Delay + Loss) shortest path"
	case MetricBandwidth:
		return "Bandwidth-based optimal path"
	default:
		return "Unknown metric"
	}
}

// ValidateLink validates link usability
func ValidateLink(link *Link) bool {
	if link == nil {
		return false
	}
	if link.Loss < 0 || link.Loss > 1 {
		return false
	}
	if link.Delay < 0 {
		return false
	}
	if !link.Status {
		return false
	}
	return true
}

// CalculatePath computes the shortest path using Dijkstra's algorithm
func (db *LSDB) CalculatePath(src, dst uint32, metric MetricType) (*PathResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// validate nodes exist
	if _, exists := db.Nodes[src]; !exists {
		return nil, errors.New("source node does not exist")
	}
	if _, exists := db.Nodes[dst]; !exists {
		return nil, errors.New("destination node does not exist")
	}

	// if source and destination are the same
	if src == dst {
		return &PathResult{
			Path:        []uint32{src},
			Links:       []string{},
			TotalDelay:  0,
			TotalLoss:   0,
			TotalCost:   0,
			Metric:      metric,
			Description: "Same source and destination",
		}, nil
	}

	// initialize data structures
	dist := make(map[uint32]float64)
	prev := make(map[uint32]uint32)
	prevLink := make(map[uint32]string) // record link ID used to reach the node
	visited := make(map[uint32]bool)
	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	// initialize distances for all nodes
	for nodeID := range db.Nodes {
		dist[nodeID] = math.Inf(1)
	}
	dist[src] = 0

	// push source node into priority queue
	heap.Push(&pq, &PathNode{NodeID: src, Distance: 0})

	// Dijkstra main loop
	for pq.Len() > 0 {
		// pop current node with smallest distance
		current := heap.Pop(&pq).(*PathNode)
		currentID := current.NodeID

		// skip if already visited
		if visited[currentID] {
			continue
		}
		visited[currentID] = true

		// if destination found, exit early
		if currentID == dst {
			break
		}

		// iterate over neighbors
		if neighbors, exists := db.Topology[currentID]; exists {
			for neighborID, linkID := range neighbors {
				// get link information
				link, exists := db.Links[linkID]
				if !exists || !ValidateLink(link) {
					continue // link does not exist or is unusable
				}

				// 计算链路成本
				cost := calculateLinkCost(link, metric)
				if math.IsInf(cost, 1) {
					continue // infinite cost, skip
				}

				// 更新距离
				newDist := dist[currentID] + cost
				if newDist < dist[neighborID] {
					dist[neighborID] = newDist
					prev[neighborID] = currentID
					prevLink[neighborID] = linkID
					heap.Push(&pq, &PathNode{NodeID: neighborID, Distance: newDist})
				}
			}
		}
	}

	// check if a path was found
	if math.IsInf(dist[dst], 1) {
		return nil, errors.New("no path found between source and destination")
	}

	// build the path
	path := make([]uint32, 0)
	links := make([]string, 0)

	// backtrack from destination to source
	current := dst
	for current != src {
		path = append([]uint32{current}, path...)

		if linkID, exists := prevLink[current]; exists {
			links = append([]string{linkID}, links...)
		}

		if prevNode, exists := prev[current]; exists {
			current = prevNode
		} else {
			return nil, errors.New("path reconstruction failed")
		}
	}
	path = append([]uint32{src}, path...)

	// compute total delay and total loss for the path
	totalDelay := 0.0
	totalLoss := 0.0
	for i := 0; i < len(path)-1; i++ {
		srcNode := path[i]
		dstNode := path[i+1]
		if linkID, exists := db.Topology[srcNode][dstNode]; exists {
			if link, exists := db.Links[linkID]; exists {
				totalDelay += float64(link.Delay)
				// composite loss: 1 - Π(1 - loss_i)
				totalLoss = 1 - (1-totalLoss)*(1-float64(link.Loss))
			}
		}
	}

	return &PathResult{
		Path:        path,
		Links:       links,
		TotalDelay:  totalDelay,
		TotalLoss:   totalLoss,
		TotalCost:   dist[dst],
		Metric:      metric,
		Description: GetMetricDescription(metric),
	}, nil
}

// CalculateAllPaths computes shortest paths from source to all nodes
func (db *LSDB) CalculateAllPaths(src uint32, metric MetricType) (map[uint32]*PathResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if _, exists := db.Nodes[src]; !exists {
		return nil, errors.New("source node does not exist")
	}

	// run Dijkstra to compute shortest distances to all nodes
	dist := make(map[uint32]float64)
	prev := make(map[uint32]uint32)
	prevLink := make(map[uint32]string)
	visited := make(map[uint32]bool)
	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	// initialization
	for nodeID := range db.Nodes {
		dist[nodeID] = math.Inf(1)
	}
	dist[src] = 0
	heap.Push(&pq, &PathNode{NodeID: src, Distance: 0})

	// Dijkstra algorithm
	for pq.Len() > 0 {
		current := heap.Pop(&pq).(*PathNode)
		currentID := current.NodeID

		if visited[currentID] {
			continue
		}
		visited[currentID] = true

		if neighbors, exists := db.Topology[currentID]; exists {
			for neighborID, linkID := range neighbors {
				link, exists := db.Links[linkID]
				if !exists || !ValidateLink(link) {
					continue
				}

				cost := calculateLinkCost(link, metric)
				if math.IsInf(cost, 1) {
					continue
				}

				newDist := dist[currentID] + cost

				if newDist < dist[neighborID] {
					dist[neighborID] = newDist
					prev[neighborID] = currentID
					prevLink[neighborID] = linkID
					heap.Push(&pq, &PathNode{NodeID: neighborID, Distance: newDist})
				}
			}
		}
	}

	// build path results for each reachable node
	results := make(map[uint32]*PathResult)
	for dst := range db.Nodes {
		if math.IsInf(dist[dst], 1) || dst == src {
			continue
		}

		// construct path
		path := make([]uint32, 0)
		links := make([]string, 0)
		current := dst

		for current != src {
			path = append([]uint32{current}, path...)

			if linkID, exists := prevLink[current]; exists {
				links = append([]string{linkID}, links...)
			}

			if prevNode, exists := prev[current]; exists {
				current = prevNode
			} else {
				break // path reconstruction failed
			}
		}
		path = append([]uint32{src}, path...)

		// compute path statistics
		totalDelay := 0.0
		totalLoss := 0.0
		for i := 0; i < len(path)-1; i++ {
			srcNode := path[i]
			dstNode := path[i+1]
			if linkID, exists := db.Topology[srcNode][dstNode]; exists {
				if link, exists := db.Links[linkID]; exists {
					totalDelay += float64(link.Delay)
					totalLoss = 1 - (1-totalLoss)*(1-float64(link.Loss))
				}
			}
		}

		results[dst] = &PathResult{
			Path:        path,
			Links:       links,
			TotalDelay:  totalDelay,
			TotalLoss:   totalLoss,
			TotalCost:   dist[dst],
			Metric:      metric,
			Description: GetMetricDescription(metric),
		}
	}

	return results, nil
}

// FindBestPath finds best paths using multiple metric types
func (db *LSDB) FindBestPath(src, dst uint32) ([]*PathResult, error) {
	results := make([]*PathResult, 0, 4)
	metricTypes := []MetricType{MetricDelay, MetricLoss, MetricComposite, MetricBandwidth}

	for _, metric := range metricTypes {
		path, err := db.CalculatePath(src, dst, metric)
		if err == nil {
			results = append(results, path)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("no valid path found with any metric")
	}

	return results, nil
}

// GetNetworkStats returns basic network statistics
func (db *LSDB) GetNetworkStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["totalNodes"] = len(db.Nodes)
	stats["totalLinks"] = len(db.Links)

	// compute number of available links
	activeLinks := 0
	totalDelay := float32(0)
	totalLoss := float32(0)

	for _, link := range db.Links {
		if link.Status {
			activeLinks++
			totalDelay += link.Delay
			totalLoss += link.Loss
		}
	}

	stats["activeLinks"] = activeLinks
	if activeLinks > 0 {
		stats["avgDelay"] = totalDelay / float32(activeLinks)
		stats["avgLoss"] = totalLoss / float32(activeLinks)
	} else {
		stats["avgDelay"] = 0
		stats["avgLoss"] = 0
	}

	return stats
}
