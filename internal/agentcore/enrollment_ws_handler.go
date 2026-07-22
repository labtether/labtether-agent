package agentcore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"

	"github.com/labtether/labtether-agent/internal/agentidentity"
	"github.com/labtether/protocol"
)

var savePendingEnrollmentToken = saveTokenToFile

// handleEnrollmentChallenge signs the hub-issued enrollment challenge with the
// agent device private key and sends enrollment.proof back to the hub.
func handleEnrollmentChallenge(transport *wsTransport, msg protocol.Message, cfg RuntimeConfig) {
	var data protocol.EnrollmentChallengeData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		log.Printf("agentws: invalid enrollment.challenge payload: %v", err)
		return
	}

	nonce := strings.TrimSpace(data.Nonce)
	connectionID := strings.TrimSpace(data.ConnectionID)
	if nonce == "" || connectionID == "" {
		log.Printf("agentws: enrollment.challenge missing nonce/connection_id")
		return
	}

	identity := transport.deviceIdentity
	if identity == nil {
		loaded, err := loadDeviceIdentity(cfg)
		if err != nil {
			log.Printf("agentws: could not load device identity for enrollment proof: %v", err)
			return
		}
		identity = loaded
		transport.deviceIdentity = loaded
	}

	signingPayload := agentidentity.BuildEnrollmentProofPayload(connectionID, nonce, identity.Fingerprint)
	signature := ed25519.Sign(identity.PrivateKey, signingPayload)

	proof := protocol.EnrollmentProofData{
		ConnectionID: connectionID,
		Nonce:        nonce,
		KeyAlgorithm: identity.KeyAlgorithm,
		PublicKey:    identity.PublicKeyBase64,
		Fingerprint:  identity.Fingerprint,
		Signature:    base64.StdEncoding.EncodeToString(signature),
	}
	rawProof, err := json.Marshal(proof)
	if err != nil {
		log.Printf("agentws: failed to marshal enrollment proof: %v", err)
		return
	}

	if err := transport.Send(protocol.Message{
		Type: protocol.MsgEnrollmentProof,
		Data: rawProof,
	}); err != nil {
		log.Printf("agentws: failed to send enrollment proof: %v", err)
		return
	}

	log.Printf("agentws: enrollment proof sent for connection_id=%s", connectionID)
}

// handleEnrollmentApproved processes an enrollment.approved message from the hub.
// It saves the token to disk, updates the transport credentials, and closes the
// current (unauthenticated) connection so the reconnect loop re-dials with the token.
func handleEnrollmentApproved(transport *wsTransport, msg protocol.Message, cfg RuntimeConfig) {
	var data protocol.EnrollmentApprovedData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		log.Printf("agentws: invalid enrollment.approved payload: %v", err)
		return
	}
	data.Token = strings.TrimSpace(data.Token)
	data.AssetID = strings.TrimSpace(data.AssetID)
	if data.Token == "" {
		log.Printf("agentws: enrollment.approved received but token is empty \u2014 ignoring")
		return
	}
	if !validPersistedAssetID(data.AssetID) {
		log.Printf("agentws: enrollment.approved received an invalid canonical asset id \u2014 ignoring")
		return
	}

	log.Printf("agentws: enrollment APPROVED! asset_id=%s", data.AssetID)
	currentIdentity := transport.identitySource().Snapshot()
	currentAPIOrigin := apiBaseURLFromWS(currentIdentity.WSBaseURL)
	if currentAPIOrigin == "" {
		currentAPIOrigin = currentIdentity.APIBaseURL
	}
	adoptedIdentity, err := transport.identitySource().AdoptCredential(
		data.Token,
		data.AssetID,
		currentIdentity.WSBaseURL,
		currentAPIOrigin,
	)
	if err != nil {
		log.Printf("agentws: enrollment.approved identity update failed: %v", err)
		return
	}

	// Persist token to disk so it survives restarts.
	credentialWarning := ""
	if cfg.TokenFilePath != "" {
		if err := savePendingEnrollmentToken(cfg.TokenFilePath, data.Token); err != nil {
			credentialWarning = agentTokenPersistenceFailed
			if removeErr := removePersistedAgentToken(cfg.TokenFilePath); removeErr != nil {
				log.Printf("agentws: ERROR: approved token is memory-only and stale token removal also failed: persist=%v remove=%v", err, removeErr)
			} else {
				log.Printf("agentws: ERROR: approved token is memory-only; stale token file removed after persistence failure: %v", err)
			}
		} else {
			log.Printf("agentws: token saved to %s", cfg.TokenFilePath)
			if err := saveEnrollmentState(cfg.TokenFilePath, enrollmentState{
				AssetID:   adoptedIdentity.AssetID,
				HubWSURL:  adoptedIdentity.WSBaseURL,
				HubAPIURL: adoptedIdentity.APIBaseURL,
			}); err != nil {
				log.Printf("agentws: warning: failed to save enrollment state: %v", err)
			}
		}
	}

	// The atomic source was updated before persistence so even a memory-only
	// approved credential immediately activates HTTP fallback and the next dial.
	transport.setCredentialPersistenceError(credentialWarning)
	transport.setCredentialError("")

	// Close current connection - the reconnect loop will re-dial using the new token.
	transport.markDisconnected()
}

// handleEnrollmentRejected processes an enrollment.rejected message from the hub.
// The agent keeps the connection open and will retry; the admin may still approve later.
func handleEnrollmentRejected(msg protocol.Message) {
	var data protocol.EnrollmentRejectedData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		log.Printf("agentws: invalid enrollment.rejected payload: %v", err)
		return
	}
	log.Printf("agentws: enrollment REJECTED: %s", data.Reason)
	// Do not disconnect - the admin might approve a pending request later via a different
	// approval flow, or the operator may re-enroll with a different token.
}
