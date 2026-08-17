package attestation

import "testing"

type receiptSink struct {
	calls   int
	receipt []byte
	digest  [32]byte
}

func (sink *receiptSink) WriteReceipt(receipt []byte, digest [32]byte) error {
	sink.calls++
	sink.receipt = append([]byte(nil), receipt...)
	sink.digest = digest
	return nil
}

func TestCheckpointHandlerRejectsUnsealedRoot(t *testing.T) {
	if NewCheckpointHandler(nil, &receiptSink{}) != nil {
		t.Fatal("accepted nil root handler")
	}
	if NewCheckpointHandler(&Handler{}, nil) != nil {
		t.Fatal("accepted nil receipt sink")
	}
}
