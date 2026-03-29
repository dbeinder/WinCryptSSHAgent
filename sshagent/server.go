package sshagent

import (
	"golang.org/x/crypto/ssh/agent"
	"io"
)

type ConnWithPID interface {
	io.ReadWriteCloser
	ClientPID() uint32
}

type Server struct {
	Agent agent.Agent
}

func (s *Server) SSHAgentHandler(conn ConnWithPID) {
	defer conn.Close()
	if s.Agent == nil {
		return
	}
	ag := s.Agent
	if pid := conn.ClientPID(); pid != 0 {
		if extAg, ok := ag.(agent.ExtendedAgent); ok {
			ag = NewProcessAwareAgent(extAg, pid)
		}
	}
	err := agent.ServeAgent(ag, conn)
	if err != nil && err != io.EOF {
		println(err.Error())
	}
}
