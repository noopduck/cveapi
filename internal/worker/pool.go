package worker

import (
	"context"
	"fmt"
	"sync"
)

// Task represents a job to be processed by the worker pool
type Task struct {
	ID       string
	FilePath string
	Data     interface{}
}

// Result represents the result of a processed task
type Result struct {
	Task  Task
	Error error
}

// Pool represents a pool of workers that can process tasks
type Pool struct {
	numWorkers int
	tasks      chan Task
	results    chan Result
	processor  func(Task) error
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewPool creates a new worker pool with the given number of workers
func NewPool(ctx context.Context, numWorkers int, processor func(Task) error) *Pool {
	ctx, cancel := context.WithCancel(ctx)
	return &Pool{
		numWorkers: numWorkers,
		tasks:      make(chan Task),
		results:    make(chan Result),
		processor:  processor,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the worker pool
func (p *Pool) Start() {
	// Start workers
	for i := 0; i < p.numWorkers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

// Submit adds a new task to the pool
func (p *Pool) Submit(task Task) {
	select {
	case p.tasks <- task:
	case <-p.ctx.Done():
		p.results <- Result{Task: task, Error: fmt.Errorf("pool is closed")}
	}
}

// Results returns the channel that will receive task results
func (p *Pool) Results() <-chan Result {
	return p.results
}

// Stop gracefully shuts down the worker pool
func (p *Pool) Stop() {
	p.cancel()
	close(p.tasks)
	p.wg.Wait()
	close(p.results)
}

func (p *Pool) worker() {
	defer p.wg.Done()

	for {
		select {
		case task, ok := <-p.tasks:
			if !ok {
				return
			}

			err := p.processor(task)
			p.results <- Result{Task: task, Error: err}

		case <-p.ctx.Done():
			return
		}
	}
}
