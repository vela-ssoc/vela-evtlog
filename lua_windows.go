//go:build windows
// +build windows

package evtlog

import (
	"github.com/vela-ssoc/vela-evtlog/watch"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/vela"
	"go.uber.org/ratelimit"
	"reflect"
	"strings"
	"time"
)

var (
	xEnv vela.Environment
	//instance *WinEv
	winEvBucketOffset = "windows_event_record_offset"
	winLoginBucket    = "windows_access_log"
	winEvTypeOf       = reflect.TypeOf((*WinEv)(nil)).String()
)

func (wv *WinEv) subscribeL(L *lua.LState) int {
	name := L.CheckString(1)
	query := L.CheckString(2)
	wv.Subscribe(name, query)
	return 0
}

func (wv *WinEv) pipeL(L *lua.LState) int {
	wv.cfg.pipe.Check(L, 1)
	return 0
}

func (wv *WinEv) toL(L *lua.LState) int {
	wv.cfg.sdk = auxlib.CheckWriter(L.Get(1), L)
	return 0
}

func (wv *WinEv) startL(L *lua.LState) int {
	xEnv.Start(L, wv).From(L.CodeVM()).Do()
	return 0
}

func (wv *WinEv) limitL(L *lua.LState) int {
	rt := L.IsInt(1)
	pt := L.IsInt(2)
	var pre time.Duration

	if pt <= 0 {
		pre = time.Second
	} else {
		pre = time.Duration(pt) * time.Second
	}

	wv.cfg.limit = ratelimit.New(rt, ratelimit.Per(pre))
	return 0
}

func (wv *WinEv) ignoreL(L *lua.LState) int {
	wv.cfg.ignore.CheckMany(L)
	return 0
}

func (wv *WinEv) filterL(L *lua.LState) int {
	wv.cfg.filter.CheckMany(L)
	return 0
}

func (wv *WinEv) Index(L *lua.LState, key string) lua.LValue {

	switch key {
	case "subscribe":
		return L.NewFunction(wv.subscribeL)
	case "pipe":
		return L.NewFunction(wv.pipeL)
	case "ignore":
		return lua.NewFunction(wv.ignoreL)
	case "filter":
		return lua.NewFunction(wv.filterL)
	case "to":
		return L.NewFunction(wv.toL)
	case "limit":
		return L.NewFunction(wv.limitL)
	case "start":
		return L.NewFunction(wv.startL)
	default:
		//todo
	}

	return lua.LNil
}

func (wv *WinEv) NewIndex(L *lua.LState, key string, val lua.LValue) {
	if strings.HasPrefix(key, "ev_") {
		wv.cfg.chains.Set(key[3:], lua.CheckFunction(L, val))
	}
}

func constructor(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewVelaData(cfg.name, winEvTypeOf)
	if proc.IsNil() {
		proc.Set(newWinEv(cfg))
	} else {
		proc.Data.(*WinEv).cfg = cfg
	}
	L.Push(proc)
	return 1
}

func WithEnv(env vela.Environment) {
	xEnv = env
	watch.WithEnv(env)
	xEnv.Set("evtlog", lua.NewFunction(constructor))
}
