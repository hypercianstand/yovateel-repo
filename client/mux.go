package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sartoopjj/vpn-over-github/shared"
)

// upstreamChannel holds the state for one pre-allocated channel (gist or git dir).
type upstreamChannel struct {
	channelID   string
	tokenIdx    int
	transport   shared.Transport
	encryptor   *shared.Encryptor
	batchSeq    atomic.Int64
	lastReadSeq atomic.Int64
	lastReadTs  atomic.Int64
}

// VirtualConn is a single SOCKS connection multiplexed over an upstream channel.
type VirtualConn struct {
	connID     string
	dst        string
	channelIdx int
	recvBuf    chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
	closeSent  atomic.Bool

	mu         sync.Mutex
	writeQueue []writeChunk
	readBuf    []byte

	seq       atomic.Int64
	bytesUp   atomic.Int64
	bytesDown atomic.Int64
	startTime time.Time
}

type writeChunk struct {
	data []byte
	seq  int64
}

// Write enqueues data to be sent to the server in the next batch.
func (vc *VirtualConn) Write(p []byte) (int, error) {
	select {
	case <-vc.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	seq := vc.seq.Add(1)
	vc.mu.Lock()
	vc.writeQueue = append(vc.writeQueue, writeChunk{data: buf, seq: seq})
	vc.mu.Unlock()
	vc.bytesUp.Add(int64(len(p)))
	return len(p), nil
}

// Read blocks until data is received from the server.
func (vc *VirtualConn) Read(p []byte) (int, error) {
	vc.mu.Lock()
	if len(vc.readBuf) > 0 {
		n := copy(p, vc.readBuf)
		vc.readBuf = vc.readBuf[n:]
		vc.mu.Unlock()
		vc.bytesDown.Add(int64(n))
		return n, nil
	}
	vc.mu.Unlock()

	select {
	case data, ok := <-vc.recvBuf:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			vc.mu.Lock()
			vc.readBuf = append(vc.readBuf[:0], data[n:]...)
			vc.mu.Unlock()
		}
		vc.bytesDown.Add(int64(n))
		return n, nil
	case <-vc.closed:
		return 0, io.EOF
	}
}

// Close signals the connection closed (sends a closing frame on next batch flush).
func (vc *VirtualConn) Close() error {
	vc.closeOnce.Do(func() { close(vc.closed) })
	return nil
}

// MuxClient manages N upstream channels per token, multiplexing all SOCKS
// connections through them using batched frames.
type MuxClient struct {
	cfg         *Config
	rateLimiter *RateLimiter
	channels    []*upstreamChannel

	mu          sync.RWMutex
	conns       map[string]*VirtualConn // connID → VirtualConn
	nextChannel int                     // round-robin index
}

// NewMuxClient creates and starts a MuxClient. It pre-allocates N channels
// per token using EnsureChannel.
func NewMuxClient(ctx context.Context, cfg *Config, rl *RateLimiter, transports map[int]shared.Transport) (*MuxClient, error) {
	n := cfg.GitHub.UpstreamConnections
	if n <= 0 {
		n = 2
	}

	m := &MuxClient{
		cfg:         cfg,
		rateLimiter: rl,
		conns:       make(map[string]*VirtualConn),
	}

	var wg sync.WaitGroup
	var initMu sync.Mutex
	var initErr error

	for tokenIdx, transport := range transports {
		wg.Add(1)
		go func(tokenIdx int, transport shared.Transport) {
			defer wg.Done()
			channels, err := m.initTokenChannels(ctx, tokenIdx, transport, n)
			initMu.Lock()
			defer initMu.Unlock()
			if err != nil {
				slog.Error("token channel initialization failed", "token_idx", tokenIdx, "error", err)
				if initErr == nil {
					initErr = err
				}
			}
			m.channels = append(m.channels, channels...)
		}(tokenIdx, transport)
	}

	wg.Wait()

	if len(m.channels) == 0 {
		if initErr != nil {
			return nil, fmt.Errorf("no upstream channels available: %w", initErr)
		}
		return nil, fmt.Errorf("no upstream channels available")
	}

	for _, ch := range m.channels {
		go m.batchWriteLoop(ctx, ch)
		go m.batchReadLoop(ctx, ch)
	}
	return m, nil
}

// Connect opens a new virtual connection to dst. Returns a VirtualConn that
// implements io.ReadWriteCloser.
func (m *MuxClient) Connect(ctx context.Context, dst string) (*VirtualConn, error) {
	connID, err := shared.GenerateConnID()
	if err != nil {
		return nil, fmt.Errorf("generating conn ID: %w", err)
	}

	m.mu.Lock()
	ch := m.channels[m.nextChannel%len(m.channels)]
	m.nextChannel++
	vc := &VirtualConn{
		connID:     connID,
		dst:        dst,
		channelIdx: m.nextChannel - 1,
		recvBuf:    make(chan []byte, 128),
		closed:     make(chan struct{}),
		startTime:  time.Now(),
	}
	m.conns[connID] = vc
	m.mu.Unlock()

	// Announce connection by enqueuing the first frame immediately.
	seq := vc.seq.Add(1)
	vc.mu.Lock()
	vc.writeQueue = append(vc.writeQueue, writeChunk{data: nil, seq: seq})
	vc.mu.Unlock()

	slog.Info("virtual connection opened", "conn_id", connID, "dst", dst, "channel", ch.channelID)
	return vc, nil
}

// CloseConn sends a FrameClosing signal and removes the connection.
func (m *MuxClient) CloseConn(_ context.Context, vc *VirtualConn) {
	vc.closeOnce.Do(func() { close(vc.closed) })
}

// CloseAll closes all connections and channels.
func (m *MuxClient) CloseAll(ctx context.Context) {
	m.mu.Lock()
	conns := make([]*VirtualConn, 0, len(m.conns))
	for _, vc := range m.conns {
		conns = append(conns, vc)
	}
	m.conns = make(map[string]*VirtualConn)
	m.mu.Unlock()

	for _, vc := range conns {
		vc.closeOnce.Do(func() { close(vc.closed) })
	}
	for _, ch := range m.channels {
		if err := ch.transport.DeleteChannel(ctx, ch.channelID); err != nil {
			slog.Warn("cleanup channel failed", "channel_id", ch.channelID, "error", err)
		}
	}
}

// Snapshot returns sorted (by start time) point-in-time view of all active connections.
func (m *MuxClient) Snapshot() []ConnSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ConnSnapshot, 0, len(m.conns))
	for _, vc := range m.conns {
		chIdx := vc.channelIdx % len(m.channels)
		ch := m.channels[chIdx]
		transport := m.cfg.GitHub.Tokens[ch.tokenIdx].Transport
		if transport == "" {
			transport = "git"
		}
		out = append(out, ConnSnapshot{
			ConnID:    vc.connID,
			Dst:       vc.dst,
			Transport: transport,
			TokenIdx:  ch.tokenIdx,
			BytesUp:   vc.bytesUp.Load(),
			BytesDown: vc.bytesDown.Load(),
			StartTime: vc.startTime,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartTime.Before(out[j].StartTime)
	})
	return out
}

// ── batch loops ────────────────────────────────────────────────────────────

func (m *MuxClient) batchWriteLoop(ctx context.Context, ch *upstreamChannel) {
	ticker := time.NewTicker(m.cfg.GitHub.BatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.flushOutbound(ctx, ch)
		}
	}
}

func (m *MuxClient) flushOutbound(ctx context.Context, ch *upstreamChannel) {
	m.mu.RLock()
	snapshot := make([]*VirtualConn, 0, len(m.conns))
	for _, vc := range m.conns {
		if vc.channelIdx%len(m.channels) == chIndex(m.channels, ch) {
			snapshot = append(snapshot, vc)
		}
	}
	m.mu.RUnlock()

	var frames []shared.Frame
	toDelete := make([]string, 0)
	for _, vc := range snapshot {
		vc.mu.Lock()
		queue := vc.writeQueue
		vc.writeQueue = nil
		vc.mu.Unlock()

		isClosed := false
		select {
		case <-vc.closed:
			isClosed = true
		default:
		}

		if len(queue) == 0 && !isClosed {
			continue
		}

		if len(queue) == 0 && isClosed {
			if vc.closeSent.Load() {
				toDelete = append(toDelete, vc.connID)
				continue
			}
			frames = append(frames, shared.Frame{
				ConnID: vc.connID,
				Seq:    vc.seq.Add(1),
				Status: shared.FrameClosing,
			})
			vc.closeSent.Store(true)
			toDelete = append(toDelete, vc.connID)
			continue
		}

		for _, chunk := range queue {
			status := shared.FrameActive
			if isClosed && chunk.seq == queue[len(queue)-1].seq {
				status = shared.FrameClosing
				vc.closeSent.Store(true)
				toDelete = append(toDelete, vc.connID)
			}
			encoded := ""
			if len(chunk.data) > 0 {
				enc, err := ch.encryptor.Encrypt(chunk.data, vc.connID, chunk.seq)
				if err != nil {
					slog.Warn("encrypt failed", "error", err)
					continue
				}
				encoded = enc
			}
			dst := ""
			if chunk.seq == 1 {
				dst = vc.dst
			}
			frames = append(frames, shared.Frame{
				ConnID: vc.connID,
				Seq:    chunk.seq,
				Dst:    dst,
				Data:   encoded,
				Status: status,
			})
		}
	}

	if len(frames) == 0 {
		if len(toDelete) > 0 {
			m.mu.Lock()
			for _, connID := range toDelete {
				delete(m.conns, connID)
			}
			m.mu.Unlock()
		}
		return
	}

	if err := m.acquireForToken(ctx, ch.tokenIdx); err != nil {
		slog.Debug("write skipped due to rate limiter", "token_idx", ch.tokenIdx, "error", err)
		return
	}

	seq := ch.batchSeq.Add(1)
	batch := &shared.Batch{
		Seq:    seq,
		Ts:     time.Now().Unix(),
		Frames: frames,
	}
	if err := ch.transport.Write(ctx, ch.channelID, shared.ClientBatchFile, batch); err != nil {
		slog.Warn("batch write failed", "channel", ch.channelID, "error", err)
		return
	}

	m.afterTransportCall(ch.tokenIdx, ch.transport)
	if wait := m.rateLimiter.RecordWrite(ch.tokenIdx); wait > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}

	if len(toDelete) > 0 {
		m.mu.Lock()
		for _, connID := range toDelete {
			delete(m.conns, connID)
		}
		m.mu.Unlock()
	}
}

func (m *MuxClient) batchReadLoop(ctx context.Context, ch *upstreamChannel) {
	timer := time.NewTimer(m.cfg.GitHub.FetchInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			m.doBatchRead(ctx, ch)

			m.mu.RLock()
			active := 0
			for _, vc := range m.conns {
				if vc.channelIdx%len(m.channels) == chIndex(m.channels, ch) {
					active++
				}
			}
			m.mu.RUnlock()

			interval := m.cfg.GitHub.FetchInterval
			if active == 0 {
				interval *= 10
				if interval > 10*time.Second {
					interval = 5 * time.Second
				}
			}
			timer.Reset(interval)
		}
	}
}

func (m *MuxClient) doBatchRead(ctx context.Context, ch *upstreamChannel) {
	if err := m.acquireForToken(ctx, ch.tokenIdx); err != nil {
		slog.Debug("read skipped due to rate limiter", "token_idx", ch.tokenIdx, "error", err)
		return
	}
	batch, err := ch.transport.Read(ctx, ch.channelID, shared.ServerBatchFile)
	m.afterTransportCall(ch.tokenIdx, ch.transport)
	if err != nil {
		slog.Debug("batch read failed", "channel", ch.channelID, "error", err)
		return
	}
	if batch == nil {
		return
	}
	lastSeq := ch.lastReadSeq.Load()
	lastTs := ch.lastReadTs.Load()
	if batch.Seq <= lastSeq && batch.Ts <= lastTs {
		return
	}
	if batch.Seq <= lastSeq && batch.Ts > lastTs {
		slog.Debug("detected server batch sequence reset", "channel", ch.channelID, "prev_seq", lastSeq, "new_seq", batch.Seq)
	}
	ch.lastReadSeq.Store(batch.Seq)
	ch.lastReadTs.Store(batch.Ts)
	m.dispatchFrames(ch, batch.Frames)
}

func (m *MuxClient) dispatchFrames(ch *upstreamChannel, frames []shared.Frame) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, f := range frames {
		vc, ok := m.conns[f.ConnID]
		if !ok {
			continue
		}
		switch f.Status {
		case shared.FrameClosed, shared.FrameError:
			vc.closeOnce.Do(func() { close(vc.closed) })
			continue
		}
		if f.Data == "" {
			continue
		}
		plaintext, err := ch.encryptor.Decrypt(f.Data, f.ConnID, f.Seq)
		if err != nil {
			slog.Warn("decrypt failed", "conn_id", f.ConnID, "error", err)
			continue
		}
		if len(plaintext) == 0 {
			continue
		}
		select {
		case vc.recvBuf <- plaintext:
		case <-vc.closed:
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func chIndex(channels []*upstreamChannel, ch *upstreamChannel) int {
	for i, c := range channels {
		if c == ch {
			return i
		}
	}
	return 0
}

func (m *MuxClient) initTokenChannels(ctx context.Context, tokenIdx int, transport shared.Transport, count int) ([]*upstreamChannel, error) {
	token := m.rateLimiter.GetToken(tokenIdx)
	encryptor := shared.NewEncryptor(shared.EncryptionAlgorithm(m.cfg.Encryption.Algorithm), token)
	channels := make([]*upstreamChannel, 0, count)

	for len(channels) < count {
		if err := m.acquireForToken(ctx, tokenIdx); err != nil {
			return channels, err
		}
		chID, err := transport.EnsureChannel(ctx, "")
		m.afterTransportCall(tokenIdx, transport)
		if err != nil {
			return channels, fmt.Errorf("token %d channel %d: %w", tokenIdx, len(channels), err)
		}
		channels = append(channels, &upstreamChannel{
			channelID: chID,
			tokenIdx:  tokenIdx,
			transport: transport,
			encryptor: encryptor,
		})
		slog.Info("upstream channel ready", "channel_id", chID, "token_idx", tokenIdx)
	}

	return channels, nil
}

func (m *MuxClient) acquireForToken(ctx context.Context, tokenIdx int) error {
	if tokenIdx >= len(m.cfg.GitHub.Tokens) {
		return nil
	}
	transport := m.cfg.GitHub.Tokens[tokenIdx].Transport
	if transport == "" {
		transport = "git"
	}
	if transport != "gist" {
		return nil
	}
	return m.rateLimiter.Acquire(ctx, tokenIdx)
}

func (m *MuxClient) afterTransportCall(tokenIdx int, transport shared.Transport) {
	m.rateLimiter.RecordTransportCall(tokenIdx)

	if tokenIdx >= len(m.cfg.GitHub.Tokens) {
		return
	}
	t := m.cfg.GitHub.Tokens[tokenIdx].Transport
	if t == "" {
		t = "git"
	}
	if t != "gist" {
		return
	}
	m.rateLimiter.UpdateFromHeaders(tokenIdx, transport.GetRateLimitInfo())
}

// Ensure VirtualConn implements io.ReadWriteCloser.
var _ io.ReadWriteCloser = (*VirtualConn)(nil)
