// Package spf contains a simple Link State Database (LSDB) representation
// used by the SPF pipeline. The LSDB is intentionally minimal for
// demonstration and testing purposes.
package spf

import (
	"container/heap"
	"encoding/json"
	"errors"
	"io/ioutil"
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
	// 添加邻居信息
	Neighbors map[uint32]string `json:"neighbors,omitempty"` // 邻居节点ID -> 链路ID
}

// Link represents a network adjacency stored in the LSDB.
type Link struct {
	InfId     string  `json:"infId"`
	SrcNode   uint32  `json:"srcNode,omitempty"`   // 源节点ID
	DstNode   uint32  `json:"dstNode,omitempty"`   // 目标节点ID
	Loss      float32 `json:"loss"`                // 丢包率 (0-1)
	Delay     float32 `json:"delay"`               // 延迟 (毫秒)
	Status    bool    `json:"status"`              // 链路状态
	Sid       string  `json:"sid"`                 // Segment ID
	Bandwidth float32 `json:"bandwidth,omitempty"` // 带宽 (可选)
}

// LSDB数据结构
type LSDB struct {
	mu    sync.RWMutex
	Nodes map[uint32]*Node `json:"nodes"` // 节点ID到节点对象的映射
	Links map[string]*Link `json:"links"` // 链路ID到链路对象的映射
	// 添加拓扑关系
	Topology map[uint32]map[uint32]string `json:"topology,omitempty"` // 源节点->目标节点->链路ID
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

	// 更新拓扑关系
	if db.Topology == nil {
		db.Topology = make(map[uint32]map[uint32]string)
	}
	if db.Topology[link.SrcNode] == nil {
		db.Topology[link.SrcNode] = make(map[uint32]string)
	}
	db.Topology[link.SrcNode][link.DstNode] = link.InfId

	// 更新节点的邻居信息
	if srcNode, exists := db.Nodes[link.SrcNode]; exists {
		if srcNode.Neighbors == nil {
			srcNode.Neighbors = make(map[uint32]string)
		}
		srcNode.Neighbors[link.DstNode] = link.InfId
	}

	// 如果是双向链路，也添加反向拓扑
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

// RemoveNode 移除节点及其相关链路
func (db *LSDB) RemoveNode(nodeID uint32) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// 移除节点
	delete(db.Nodes, nodeID)

	// 移除拓扑中与该节点相关的所有链路
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

	// 从其他节点的邻居中移除该节点
	for _, node := range db.Nodes {
		delete(node.Neighbors, nodeID)
	}
}

// RemoveLink 移除链路
func (db *LSDB) RemoveLink(linkID string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	link, exists := db.Links[linkID]
	if !exists {
		return
	}

	// 移除链路
	delete(db.Links, linkID)

	// 更新拓扑
	if targets, exists := db.Topology[link.SrcNode]; exists {
		delete(targets, link.DstNode)
		if len(targets) == 0 {
			delete(db.Topology, link.SrcNode)
		}
	}

	// 如果是双向链路，也移除反向拓扑
	if link.Status {
		if targets, exists := db.Topology[link.DstNode]; exists {
			delete(targets, link.SrcNode)
			if len(targets) == 0 {
				delete(db.Topology, link.DstNode)
			}
		}
	}

	// 更新节点的邻居信息
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

// ==================== 持久化功能 ====================

// SaveJSON 保存LSDB到JSON文件
func SaveJSON(filename string, db *LSDB) error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// 序列化数据
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	return ioutil.WriteFile(filename, data, 0644)
}

// LoadJSON 从JSON文件加载LSDB
func LoadJSON(filename string, db *LSDB) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// 读取文件
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	// 反序列化到临时结构体
	tempDB := &LSDB{}
	if err := json.Unmarshal(data, tempDB); err != nil {
		return err
	}

	// 复制数据到目标LSDB
	db.Nodes = tempDB.Nodes
	db.Links = tempDB.Links

	// 重建拓扑关系
	db.Topology = make(map[uint32]map[uint32]string)
	for _, link := range db.Links {
		if db.Topology[link.SrcNode] == nil {
			db.Topology[link.SrcNode] = make(map[uint32]string)
		}
		db.Topology[link.SrcNode][link.DstNode] = link.InfId

		// 如果是双向链路，添加反向拓扑
		if link.Status {
			if db.Topology[link.DstNode] == nil {
				db.Topology[link.DstNode] = make(map[uint32]string)
			}
			db.Topology[link.DstNode][link.SrcNode] = link.InfId
		}
	}

	// 重建节点的邻居信息
	for _, node := range db.Nodes {
		node.Neighbors = make(map[uint32]string)
	}

	for srcNodeID, targets := range db.Topology {
		for dstNodeID, linkID := range targets {
			if srcNode, exists := db.Nodes[srcNodeID]; exists {
				srcNode.Neighbors[dstNodeID] = linkID
			}
			if dstNode, exists := db.Nodes[dstNodeID]; exists {
				// 如果是双向链路，添加反向邻居
				if link, exists := db.Links[linkID]; exists && link.Status {
					dstNode.Neighbors[srcNodeID] = linkID
				}
			}
		}
	}

	return nil
}

// SaveLSDB persists the provided LSDB to a JSON file (`lsdb.json`).
func SaveLSDB(db *LSDB) {
	// Persist LSDB to `lsdb.json` in the current working directory.
	if err := SaveJSON("lsdb.json", db); err != nil {
		// 可以添加日志记录
		// log.Printf("Failed to save LSDB: %v", err)
	}
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

// LoadOrCreateLSDB 加载LSDB，如果文件不存在则创建新的
func LoadOrCreateLSDB(filename string) *LSDB {
	db := NewLSDB()
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// 文件不存在，返回空LSDB
		return db
	}

	if err := LoadJSON(filename, db); err != nil {
		// 加载失败，返回空LSDB
		return NewLSDB()
	}

	return db
}

// ==================== Dijkstra 算法实现 ====================

// MetricType 定义了路径计算的度量类型
type MetricType int

const (
	MetricDelay     MetricType = iota // 基于延迟
	MetricLoss                        // 基于丢包率
	MetricComposite                   // 基于延迟和丢包率的复合度量
	MetricBandwidth                   // 基于带宽（成本与带宽成反比）
)

// PathNode 用于Dijkstra算法的优先队列
type PathNode struct {
	NodeID   uint32
	Distance float64
	Index    int // 在堆中的索引
}

// PriorityQueue 实现优先队列
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

// PathResult 存储路径计算结果
type PathResult struct {
	Path        []uint32   `json:"path"`        // 节点路径
	Links       []string   `json:"links"`       // 链路ID路径
	TotalDelay  float64    `json:"totalDelay"`  // 总延迟(ms)
	TotalLoss   float64    `json:"totalLoss"`   // 总丢包率（复合）
	TotalCost   float64    `json:"totalCost"`   // 总成本（根据度量类型）
	Metric      MetricType `json:"metric"`      // 使用的度量类型
	Description string     `json:"description"` // 路径描述
}

// calculateLinkCost 计算链路成本
func calculateLinkCost(link *Link, metric MetricType) float64 {
	switch metric {
	case MetricDelay:
		return float64(link.Delay)
	case MetricLoss:
		// 将丢包率转换为成本（丢包率越高，成本越高）
		if link.Loss <= 0 {
			return 0.1 // 最小成本
		}
		return float64(link.Loss * 100) // 放大100倍以匹配延迟的单位
	case MetricComposite:
		// 复合度量：延迟 * (1 + 丢包率惩罚)
		// 丢包率越高，惩罚越大
		lossPenalty := 1.0 + float64(link.Loss)*50.0
		return float64(link.Delay) * lossPenalty
	case MetricBandwidth:
		// 基于带宽：带宽越大，成本越低
		if link.Bandwidth <= 0 {
			return math.Inf(1) // 无效带宽
		}
		// 使用 1/bandwidth 作为成本
		return 1000.0 / float64(link.Bandwidth) // 假设带宽单位是Mbps
	default:
		return float64(link.Delay)
	}
}

// GetMetricDescription 获取度量类型的描述
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

// ValidateLink 验证链路的有效性
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

// CalculatePath 使用Dijkstra算法计算最短路径
func (db *LSDB) CalculatePath(src, dst uint32, metric MetricType) (*PathResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// 验证节点存在
	if _, exists := db.Nodes[src]; !exists {
		return nil, errors.New("source node does not exist")
	}
	if _, exists := db.Nodes[dst]; !exists {
		return nil, errors.New("destination node does not exist")
	}

	// 如果是同一个节点
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

	// 初始化数据结构
	dist := make(map[uint32]float64)
	prev := make(map[uint32]uint32)
	prevLink := make(map[uint32]string) // 记录到达节点的链路ID
	visited := make(map[uint32]bool)
	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	// 初始化所有节点的距离
	for nodeID := range db.Nodes {
		dist[nodeID] = math.Inf(1)
	}
	dist[src] = 0

	// 将源节点加入优先队列
	heap.Push(&pq, &PathNode{NodeID: src, Distance: 0})

	// Dijkstra算法主循环
	for pq.Len() > 0 {
		// 获取当前最小距离节点
		current := heap.Pop(&pq).(*PathNode)
		currentID := current.NodeID

		// 如果已经访问过，跳过
		if visited[currentID] {
			continue
		}
		visited[currentID] = true

		// 如果找到目标节点，提前退出
		if currentID == dst {
			break
		}

		// 遍历邻居节点
		if neighbors, exists := db.Topology[currentID]; exists {
			for neighborID, linkID := range neighbors {
				// 获取链路信息
				link, exists := db.Links[linkID]
				if !exists || !ValidateLink(link) {
					continue // 链路不存在或不可用
				}

				// 计算链路成本
				cost := calculateLinkCost(link, metric)
				if math.IsInf(cost, 1) {
					continue // 无限成本，跳过
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

	// 检查是否找到路径
	if math.IsInf(dist[dst], 1) {
		return nil, errors.New("no path found between source and destination")
	}

	// 构建路径
	path := make([]uint32, 0)
	links := make([]string, 0)

	// 从目标节点回溯到源节点
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

	// 计算路径的总延迟和总丢包率
	totalDelay := 0.0
	totalLoss := 0.0
	for i := 0; i < len(path)-1; i++ {
		srcNode := path[i]
		dstNode := path[i+1]
		if linkID, exists := db.Topology[srcNode][dstNode]; exists {
			if link, exists := db.Links[linkID]; exists {
				totalDelay += float64(link.Delay)
				// 计算复合丢包率：1 - ∏(1 - loss_i)
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

// CalculateAllPaths 计算从源节点到所有节点的最短路径
func (db *LSDB) CalculateAllPaths(src uint32, metric MetricType) (map[uint32]*PathResult, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if _, exists := db.Nodes[src]; !exists {
		return nil, errors.New("source node does not exist")
	}

	// 使用Dijkstra计算到所有节点的最短距离
	dist := make(map[uint32]float64)
	prev := make(map[uint32]uint32)
	prevLink := make(map[uint32]string)
	visited := make(map[uint32]bool)
	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	// 初始化
	for nodeID := range db.Nodes {
		dist[nodeID] = math.Inf(1)
	}
	dist[src] = 0
	heap.Push(&pq, &PathNode{NodeID: src, Distance: 0})

	// Dijkstra算法
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

	// 为每个可达节点构建路径结果
	results := make(map[uint32]*PathResult)
	for dst := range db.Nodes {
		if math.IsInf(dist[dst], 1) || dst == src {
			continue
		}

		// 构建路径
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
				break // 路径重建失败
			}
		}
		path = append([]uint32{src}, path...)

		// 计算路径统计
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

// FindBestPath 根据多种度量类型寻找最佳路径
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

// GetNetworkStats 获取网络统计信息
func (db *LSDB) GetNetworkStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["totalNodes"] = len(db.Nodes)
	stats["totalLinks"] = len(db.Links)

	// 计算可用链路数
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
