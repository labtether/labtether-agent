package freebsd

import "github.com/labtether/labtether-agent/internal/agentplatform/generic"

func New(assetID, source string) *generic.Provider {
	return generic.New(assetID, source, "rc-helper")
}
