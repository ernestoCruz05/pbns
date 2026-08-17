package recovery

import (
	"context"
	"errors"
	"reflect"

	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

var ErrEvaluationConfig = errors.New("invalid recovery evaluation configuration")

type EvaluationFault string

const (
	EvaluationFaultInterruptAfterData7    EvaluationFault = "interrupt-after-data-7"
	EvaluationFaultArtifactDigestMismatch EvaluationFault = "artifact-digest-mismatch"
	EvaluationFaultChunkSequence          EvaluationFault = "chunk-sequence"
)

type EvaluationEvent struct {
	Connection uint64          `json:"connection"`
	Operation  string          `json:"operation"`
	Frame      string          `json:"frame"`
	Sequence   uint32          `json:"sequence"`
	Next       uint32          `json:"next"`
	Window     uint32          `json:"window"`
	Fault      EvaluationFault `json:"fault"`
	Outcome    string          `json:"outcome"`
}

type EvaluationObserver interface {
	Record(EvaluationEvent) error
}

type evaluationPlan struct {
	fault           EvaluationFault
	observer        EvaluationObserver
	newStreamSender recoverySenderFactory
}

type evaluationHandler struct {
	service *Service
	plan    evaluationPlan
}

func NewEvaluationHandler(service *Service, fault EvaluationFault,
	observer EvaluationObserver) (server.Handler, error) {
	if service == nil || nilEvaluationObserver(observer) || !validEvaluationFault(fault) {
		return nil, ErrEvaluationConfig
	}
	return &evaluationHandler{
		service: service,
		plan:    evaluationPlan{fault: fault, observer: observer},
	}, nil
}

func nilEvaluationObserver(observer EvaluationObserver) bool {
	if observer == nil {
		return true
	}
	value := reflect.ValueOf(observer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func validEvaluationFault(fault EvaluationFault) bool {
	switch fault {
	case EvaluationFaultInterruptAfterData7,
		EvaluationFaultArtifactDigestMismatch, EvaluationFaultChunkSequence:
		return true
	default:
		return false
	}
}

func (handler *evaluationHandler) Handle(ctx context.Context, frame wire.Frame,
	stream *server.Stream) error {
	if handler == nil || handler.service == nil {
		return server.ErrArgument
	}
	return handler.service.handle(ctx, frame, stream, &handler.plan)
}
