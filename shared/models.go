package shared

import "time"

const (
	// ChannelDescPrefix is the gist description prefix used to identify tunnel channels.
	ChannelDescPrefix = "gist-tunnel-ch"
	// ClientBatchFile is the file written by the client side of a channel.
	ClientBatchFile = "client.json"
	// ServerBatchFile is the file written by the server side of a channel.
	ServerBatchFile = "server.json"
	// MaxFrameDataSize is the max plaintext bytes per frame.
	MaxFrameDataSize = 512 * 1024
)

// FrameStatus is the state of a virtual connection within the mux.
type FrameStatus string

const (
	FrameActive  FrameStatus = "active"
	FrameClosing FrameStatus = "closing"
	FrameClosed  FrameStatus = "closed"
	FrameError   FrameStatus = "error"
)

// Frame carries data for one virtual connection within a multiplexed Batch.
type Frame struct {
	ConnID string      `json:"id"`
	Seq    int64       `json:"seq"`
	Dst    string      `json:"dst,omitempty"`
	Data   string      `json:"data,omitempty"` // base64-encoded encrypted payload
	Status FrameStatus `json:"status"`
	Error  string      `json:"err,omitempty"`
}

// Batch is the top-level object written to a channel file.
// Readers use Seq to detect new batches (skip if Seq ≤ last seen).
type Batch struct {
	Seq    int64   `json:"seq"`
	Ts     int64   `json:"ts"`
	Frames []Frame `json:"frames"`
}

// ChannelInfo describes one transport channel (gist or git directory).
type ChannelInfo struct {
	ID          string
	Description string
	UpdatedAt   time.Time
}

// TokenState holds per-token rate-limit and write-counter state.
type TokenState struct {
	Token              string
	RateLimitRemaining int
	RateLimitTotal     int
	RateLimitReset     time.Time
	BackoffUntil       time.Time
	BackoffLevel       int
	LastSecondStart    time.Time
	RequestsThisSecond int
	WriteMinuteStart   time.Time
	WritesThisMinute   int
	WriteHourStart     time.Time
	WritesThisHour     int
	TotalAPICalls      int64
	Priority           int
}

func MaskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "****" + token[len(token)-4:]
}

// BatchAge returns the age of a batch in seconds based on its Ts field.
func (b *Batch) Age() time.Duration {
	if b == nil || b.Ts == 0 {
		return 0
	}
	return time.Since(time.Unix(b.Ts, 0))
}
