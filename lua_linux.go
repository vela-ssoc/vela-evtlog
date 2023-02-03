package evtlog

import (
	"github.com/vela-ssoc/vela-kit/vela"
)

var xEnv vela.Environment

func WithEnv(env vela.Environment) {
	xEnv = env
	xEnv.Warn("not support evtlog with linux")
}
