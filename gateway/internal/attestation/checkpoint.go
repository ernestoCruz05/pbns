package attestation

import (
	"context"

	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

// ReceiptSink persists a signed receipt and its evidence digest after trusted verification.
type ReceiptSink interface {
	WriteReceipt(receipt []byte, evidenceDigest [32]byte) error
}

type checkpointHandler struct{ handler *Handler }

func NewCheckpointHandler(root *Handler, sink ReceiptSink) server.Handler {
	if root == nil || sink == nil || root.service == nil || root.verifier == nil || root.receiptSigner == nil || root.random == nil || root.receiptSink != nil {
		return nil
	}
	copy := *root
	copy.receiptSink = sink
	return &checkpointHandler{handler: &copy}
}

func (checkpoint *checkpointHandler) Handle(ctx context.Context, request wire.Frame, stream *server.Stream) error {
	if checkpoint == nil || checkpoint.handler == nil {
		return protocolError(13, "receipt_checkpoint_failure")
	}
	return checkpoint.handler.Handle(ctx, request, stream)
}

var _ server.Handler = (*checkpointHandler)(nil)
