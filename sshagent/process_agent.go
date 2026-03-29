package sshagent

import (
	"github.com/buptczq/WinCryptSSHAgent/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ProcessAwareAgent struct {
	inner        agent.ExtendedAgent
	pid          uint32
	processChain string
	resolved     bool
}

func NewProcessAwareAgent(inner agent.ExtendedAgent, pid uint32) *ProcessAwareAgent {
	return &ProcessAwareAgent{
		inner: inner,
		pid:   pid,
	}
}

func (p *ProcessAwareAgent) resolveChain() string {
	if !p.resolved {
		p.processChain = utils.GetProcessChain(p.pid)
		p.resolved = true
	}
	return p.processChain
}

func (p *ProcessAwareAgent) List() ([]*agent.Key, error) {
	return p.inner.List()
}

func (p *ProcessAwareAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return p.SignWithFlags(key, data, 0)
}

func (p *ProcessAwareAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	chain := p.resolveChain()
	if chain == "" {
		chain = "Unknown Source"
	}
	utils.Notify("Signing Request", chain)
	defer utils.DismissNotify()
	return p.inner.SignWithFlags(key, data, flags)
}

func (p *ProcessAwareAgent) Add(key agent.AddedKey) error {
	return p.inner.Add(key)
}

func (p *ProcessAwareAgent) Remove(key ssh.PublicKey) error {
	return p.inner.Remove(key)
}

func (p *ProcessAwareAgent) RemoveAll() error {
	return p.inner.RemoveAll()
}

func (p *ProcessAwareAgent) Lock(passphrase []byte) error {
	return p.inner.Lock(passphrase)
}

func (p *ProcessAwareAgent) Unlock(passphrase []byte) error {
	return p.inner.Unlock(passphrase)
}

func (p *ProcessAwareAgent) Signers() ([]ssh.Signer, error) {
	return p.inner.Signers()
}

func (p *ProcessAwareAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return p.inner.Extension(extensionType, contents)
}
