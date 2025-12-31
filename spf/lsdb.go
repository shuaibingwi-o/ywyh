package spf

import (
	"sync"
)

// LSDB placeholder.
// reconstructPath 从prev映射表中重建从起点到终点的完整路径

// LSDB数据结构
type LSDB struct {
	mu sync.RWMutex
}
