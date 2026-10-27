package agent

import (
	"container/list"
	"sync"
)

// jobDedup tracks recently seen job IDs so duplicate deploy events
// (SSE reconnects, retries) do not start the same job twice.
type jobDedup struct {
	mu    sync.Mutex
	max   int
	set   map[string]*list.Element
	order *list.List
}

func newJobDedup(max int) *jobDedup {
	if max <= 0 {
		max = 1024
	}
	return &jobDedup{max: max, set: make(map[string]*list.Element, max), order: list.New()}
}

// seen returns true if id was already recorded. On false, id is recorded.
func (d *jobDedup) seen(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.set[id]; ok {
		return true
	}
	el := d.order.PushBack(id)
	d.set[id] = el
	for d.order.Len() > d.max {
		front := d.order.Front()
		delete(d.set, front.Value.(string))
		d.order.Remove(front)
	}
	return false
}
