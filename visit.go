//go:build windows
// +build windows

package evtlog

func (wv *WinEv) Subscribe(name, query string) {
	if !wv.inChannel(name) {
		wv.cfg.channel = append(wv.cfg.channel, channel{name, query})
	}
}
