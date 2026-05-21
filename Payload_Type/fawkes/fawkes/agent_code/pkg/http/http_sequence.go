package http

// nextSeq returns the next monotonic sequence number for outbound messages.
// The counter starts at 1 (0 means "no sequence" for backward compatibility).
func (h *HTTPProfile) nextSeq() uint64 {
	return h.outSeq.Add(1)
}
