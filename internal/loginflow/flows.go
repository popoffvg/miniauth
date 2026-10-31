package loginflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/users"
)

// Store is the persistence port for login flows.
// Load and Write are the sfsm.Store methods. Write MUST wrap sfsm.ErrStaleState
// when the row version is no longer prev.Version. Write MUST delete the row when next is final.
// Create inserts a new flow. SecretHash returns the stored hash.
// Cleanup deletes expired rows.
type Store interface {
	Create(ctx context.Context, flow LoginFlow, hash SecretHash) error
	Load(ctx context.Context, id FlowID) (LoginFlow, error)
	Write(ctx context.Context, id FlowID, prev, next LoginFlow) error
	SecretHash(ctx context.Context, id FlowID) (SecretHash, error)
	Cleanup(ctx context.Context) error
}

// LoginFlows starts and opens login flows.
type LoginFlows struct {
	store Store
	now   func() time.Time
}

// NewLoginFlows returns a service that reads the clock from time.Now.
func NewLoginFlows(store Store) *LoginFlows {
	return &LoginFlows{store: store, now: time.Now}
}

// Start creates a KindLogin flow in StateAwaiting and returns its id and secret.
// The secret is returned once. Only its hash is stored.
func (s *LoginFlows) Start(ctx context.Context, returnURL ReturnURL) (FlowID, FlowSecret, error) {
	return s.start(ctx, LoginFlow{ReturnURL: returnURL, Kind: KindLogin})
}

// StartStepUp creates a KindStepUp flow that only a factor of userID completes.
func (s *LoginFlows) StartStepUp(ctx context.Context, userID users.ID, returnURL ReturnURL) (FlowID, FlowSecret, error) {
	if userID == (users.ID{}) {
		return "", FlowSecret{}, errors.New("loginflow: step-up user is empty")
	}
	return s.start(ctx, LoginFlow{ReturnURL: returnURL, Kind: KindStepUp, UserID: userID})
}

func (s *LoginFlows) start(ctx context.Context, flow LoginFlow) (FlowID, FlowSecret, error) {
	if err := s.store.Cleanup(ctx); err != nil {
		return "", FlowSecret{}, err
	}
	if flow.ReturnURL == "" {
		return "", FlowSecret{}, ErrReturnURL
	}
	id, err := NewFlowID()
	if err != nil {
		return "", FlowSecret{}, err
	}
	secret, err := NewFlowSecret()
	if err != nil {
		return "", FlowSecret{}, err
	}
	flow.ID = id
	flow.ExpiresAt = s.now().UTC().Add(FlowTTL)
	flow.State = StateAwaiting
	hash, err := secret.Hash()
	if err != nil {
		return "", FlowSecret{}, err
	}
	if err := s.store.Create(ctx, flow, hash); err != nil {
		return "", FlowSecret{}, err
	}
	return id, secret, nil
}

// Open checks the secret and returns a machine on the stored flow.
// The machine writes each new state through the store.
func (s *LoginFlows) Open(ctx context.Context, id FlowID, secret FlowSecret) (*sfsm.PersistedSFSM[FlowID, LoginFlow, Event], error) {
	if err := s.store.Cleanup(ctx); err != nil {
		return nil, err
	}
	hash, err := s.store.SecretHash(ctx, id)
	if err != nil {
		return nil, err
	}
	if !secret.Matches(hash) {
		return nil, ErrFlowNotFound
	}
	machine, err := sfsm.OpenPersistedSFSM(ctx, s.store, id, LoginFlow.Next, nil)
	if err != nil {
		if errors.Is(err, ErrFlowNotFound) {
			return nil, ErrFlowNotFound
		}
		return nil, fmt.Errorf("loginflow: open: %w", err)
	}
	return machine, nil
}
