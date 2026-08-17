package attestation

import (
	"context"
	"errors"
	"io"
	"log"

	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

const (
	OperationIssue  = uint64(1)
	OperationSubmit = uint64(2)
)

type WireRequest struct {
	Operation          uint64   `cbor:"1,keyasint"`
	HostFingerprint    [32]byte `cbor:"2,keyasint"`
	ChallengeRequestID [16]byte `cbor:"3,keyasint"`
}

type WireResponse struct {
	Operation          uint64   `cbor:"1,keyasint"`
	ChallengeRequestID [16]byte `cbor:"2,keyasint"`
	VerifierNonce      [32]byte `cbor:"3,keyasint"`
	RecipientKID       []byte   `cbor:"4,keyasint"`
	Object             []byte   `cbor:"5,keyasint"`
	EvidenceDigest     [32]byte `cbor:"6,keyasint"`
	BaselineID         [32]byte `cbor:"7,keyasint"`
}

// Handler is the only production wire adapter for attestation. It requires the
// same concrete TPM verifier installed at the service's immutable handoff.
type Handler struct {
	service       *Service
	verifier      *Verifier
	receiptSigner *keys.AuthorizedSigner
	random        io.Reader
	receiptSink   ReceiptSink
}

func NewHandler(service *Service, verifier *Verifier, receiptSigner *keys.AuthorizedSigner, random io.Reader) (*Handler, error) {
	if service == nil || verifier == nil || receiptSigner == nil || random == nil || !rootVerifierMatches(service.verifier, verifier) || receiptSigner.RequireRole(keys.RoleAttestationReceipt) != nil {
		return nil, ErrInvalid
	}
	return &Handler{service: service, verifier: verifier, receiptSigner: receiptSigner, random: random}, nil
}

func rootVerifierMatches(consumer EvidenceConsumer, root *Verifier) bool {
	if consumer == root {
		return true
	}
	candidate, ok := consumer.(*baselineCandidateVerifier)
	return ok && candidate.root == root
}

func (handler *Handler) Handle(ctx context.Context, request wire.Frame, stream *server.Stream) error {
	if handler == nil || handler.service == nil || handler.verifier == nil || ctx == nil || stream == nil || request.Service != wire.ServicePlatformAttestation || request.Type != wire.MessageRequest || request.Sequence != 0 || len(request.Payload) == 0 {
		return protocolError(3, "invalid_attestation_request")
	}
	var operation WireRequest
	if decodeCanonical(request.Payload, &operation) != nil {
		return protocolError(3, "invalid_attestation_request")
	}
	switch operation.Operation {
	case OperationIssue:
		return handler.issue(request, stream, operation)
	case OperationSubmit:
		return handler.submit(ctx, request, stream, operation)
	default:
		return protocolError(3, "invalid_attestation_operation")
	}
}

func (handler *Handler) issue(request wire.Frame, stream *server.Stream, operation WireRequest) error {
	log.Printf("[PBNS-ATTEST] Received issue challenge request for host %x", operation.HostFingerprint[:8])
	if allZero(operation.HostFingerprint[:]) || operation.ChallengeRequestID != ([16]byte{}) {
		log.Printf("[PBNS-ATTEST] Invalid challenge request format")
		return protocolError(3, "invalid_attestation_request")
	}
	issued, err := handler.service.Issue(operation.HostFingerprint)
	if err != nil {
		log.Printf("[PBNS-ATTEST] Service.Issue error: %v", err)
		return attestationProtocolError(err)
	}
	record, err := handler.service.store.GetAttestationChallenge(issued.RequestID)
	if err != nil {
		log.Printf("[PBNS-ATTEST] GetAttestationChallenge error: %v", err)
		return protocolError(13, "attestation_service_failure")
	}
	log.Printf("[PBNS-ATTEST] Issued challenge RequestID=%x RecipientKID=%s", issued.RequestID[:8], string(record.RecipientKID))
	response := WireResponse{Operation: OperationIssue, ChallengeRequestID: issued.RequestID, VerifierNonce: record.VerifierNonce, RecipientKID: append([]byte(nil), record.RecipientKID...), Object: append([]byte(nil), issued.Signed...)}
	return sendWireResponse(stream, request, response)
}

func (handler *Handler) submit(ctx context.Context, request wire.Frame, stream *server.Stream, operation WireRequest) error {
	log.Printf("[PBNS-ATTEST] Received submit request for ChallengeRequestID=%x", operation.ChallengeRequestID[:8])
	if operation.HostFingerprint != ([32]byte{}) || allZero(operation.ChallengeRequestID[:]) || wire.RequestID(operation.ChallengeRequestID) != request.RequestID {
		log.Printf("[PBNS-ATTEST] Invalid submit request format")
		return protocolError(3, "invalid_attestation_request")
	}
	ciphertext, err := receiveCiphertext(ctx, stream, request)
	if err != nil {
		log.Printf("[PBNS-ATTEST] receiveCiphertext error: %v", err)
		return err
	}
	defer clear(ciphertext)
	verified, err := handler.service.Submit(ctx, operation.ChallengeRequestID, ciphertext)
	if err != nil {
		log.Printf("[PBNS-ATTEST] Service.Submit error: %v", err)
		return attestationProtocolError(err)
	}
	verdict := handler.verifier.Assess(verified)
	log.Printf("[PBNS-ATTEST] Assessment verdict: trusted=%v quote=%v baseline=%v", verdict.Trusted(), verdict.Quote.Reason, verdict.MeasurementBaseline.Reason)
	if !verdict.Trusted() {
		reason := firstReason(verdict)
		log.Printf("[PBNS-ATTEST] Attestation rejected: reason=%s", reason)
		return protocolError(14, string(reason))
	}
	receipt, err := IssueReceipt(handler.receiptSigner, handler.random, ReceiptInput{RequestID: verified.Challenge.Context.RequestID, VerifierNonce: verified.Challenge.VerifierNonce, HostFingerprint: verified.Host.Fingerprint, EvidenceDigest: verified.Digest, BaselineID: verified.Host.BaselineID, Assurance: verified.Host.Assurance, Verdict: verdict})
	if err != nil {
		log.Printf("[PBNS-ATTEST] IssueReceipt error: %v", err)
		return protocolError(13, "receipt_failure")
	}
	if handler.receiptSink != nil && handler.receiptSink.WriteReceipt(append([]byte(nil), receipt...), verified.Digest) != nil {
		log.Printf("[PBNS-ATTEST] WriteReceipt sink error")
		return protocolError(13, "receipt_checkpoint_failure")
	}
	log.Printf("[PBNS-ATTEST] Attestation SUCCESS, sending signed receipt for host %x", verified.Host.Fingerprint[:8])
	response := WireResponse{Operation: OperationSubmit, ChallengeRequestID: operation.ChallengeRequestID, Object: receipt, EvidenceDigest: verified.Digest, BaselineID: verified.Host.BaselineID}
	return sendWireResponse(stream, request, response)
}

func receiveCiphertext(ctx context.Context, stream *server.Stream, request wire.Frame) ([]byte, error) {
	ciphertext := make([]byte, 0, 64*1024)
	var sequence uint32
	for {
		frame, err := stream.ReceiveUpload(ctx)
		if err != nil {
			clear(ciphertext)
			return nil, protocolError(3, "attestation_upload_invalid")
		}
		if frame.Type == wire.MessageCancel {
			clear(ciphertext)
			return nil, protocolError(8, "attestation_upload_cancelled")
		}
		if frame.Sequence != sequence {
			clear(ciphertext)
			return nil, protocolError(3, "attestation_upload_sequence")
		}
		if frame.Type == wire.MessageComplete {
			if len(ciphertext) == 0 {
				return nil, protocolError(3, "attestation_upload_empty")
			}
			return ciphertext, nil
		}
		if frame.Type != wire.MessageData || len(frame.Payload) == 0 || len(frame.Payload) > maxEncryptedEvidenceSize-len(ciphertext) {
			clear(ciphertext)
			return nil, protocolError(3, "attestation_upload_limit")
		}
		ciphertext = append(ciphertext, frame.Payload...)
		if sequence == ^uint32(0) {
			clear(ciphertext)
			return nil, protocolError(3, "attestation_upload_sequence")
		}
		sequence++
	}
}

func sendWireResponse(stream *server.Stream, request wire.Frame, response WireResponse) error {
	payload, err := canonicalMode.Marshal(response)
	if err != nil || len(payload) > wire.ControlPayloadMax {
		return protocolError(13, "attestation_response_failure")
	}
	return stream.Send(wire.Frame{Service: request.Service, Type: wire.MessageResponse, RequestID: request.RequestID, Sequence: 0, Payload: payload})
}

func protocolError(code uint64, detail string) error {
	return &server.ProtocolError{Code: code, Detail: detail}
}

func attestationProtocolError(err error) error {
	var verification *VerificationError
	switch {
	case errors.As(err, &verification):
		return protocolError(14, string(firstReason(verification.Verdict)))
	case errors.Is(err, ErrChallenge):
		return protocolError(9, "challenge_unavailable")
	case errors.Is(err, ErrDecryption):
		return protocolError(14, "ciphertext_authentication")
	case errors.Is(err, ErrAuthentication):
		return protocolError(14, "host_signature")
	case errors.Is(err, ErrContext):
		return protocolError(14, "evidence_context")
	case errors.Is(err, ErrInvalid):
		return protocolError(3, "invalid_attestation_object")
	default:
		return protocolError(13, "attestation_service_failure")
	}
}

func firstReason(verdict Verdict) Reason {
	for _, check := range []Check{verdict.Quote, verdict.EventLog, verdict.MeasurementBaseline, verdict.InventoryDrift, verdict.Capability} {
		if check.Reason != ReasonTrusted && check.Reason != ReasonSkipped {
			return check.Reason
		}
	}
	return ReasonIdentityAssociation
}
