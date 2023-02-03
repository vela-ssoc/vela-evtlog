//go:build windows
// +build windows

package watch

import (
	"encoding/xml"
	auxlib2 "github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/kind"
	"github.com/vela-ssoc/vela-kit/lua"
	"sync"
	"time"
)

type EventDataKV struct {
	Text string `xml:",chardata"`
	Name string `xml:"Name,attr"`
}

type EventData struct {
	Text string        `xml:",chardata"`
	Data []EventDataKV `xml:"Data"`
}

type Provider struct {
	Name            string `xml:"Name,attr"`
	GUID            string `xml:"Guid,attr"`
	EventSourceName string `xml:"EventSourceName,attr"`
}

type XmlEvent struct {
	XMLName     xml.Name  `xml:"Event"`
	Text        string    `xml:",chardata"`
	Xmlns       string    `xml:"xmlns,attr"`
	EvData      EventData `xml:"EventData"`
	UvData      EventData `xml:"UserData"`
	Correlation string    `xml:"System>Correlation"`
	Provider    Provider  `xml:"System>Provider"`
	User        SID       `xml:"System>Security"`
	err         error
}

// Stores the common fields from a log vela-event
type WinLogEvent struct {
	XmlText string `lua:"xml_text"`
	XmlErr  error  `lua:"xml_err"`

	// From EvtRender
	ProviderName      string    `lua:"provider_name"`
	EventId           uint64    `lua:"event_id"`
	Qualifiers        uint64    `lua:"qualifiers"`
	Level             uint64    `lua:"level"`
	Task              uint64    `lua:"task"`
	Opcode            uint64    `lua:"opcode"`
	Created           time.Time `lua:"created"`
	RecordId          uint64    `lua:"record_id"`
	ProcessId         uint64    `lua:"process_id"`
	ThreadId          uint64    `lua:"thread_id"`
	Channel           string    `lua:"channel"`
	ComputerName      string    `lua:"computer_name"`
	Version           uint64    `lua:"version"`
	RenderedFieldsErr error     `lua:"rendered_fields_err"`

	// From EvtFormatMessage
	Msg                string `lua:"msg"`
	LevelText          string `lua:"level_text"`
	TaskText           string `lua:"task_text"`
	OpcodeText         string `lua:"opcode_text"`
	Keywords           string `lua:"keywords"`
	ChannelText        string `lua:"channel_text"`
	ProviderText       string `lua:"provider_text"`
	IdText             string `lua:"id_text"`
	PublisherHandleErr error  `lua:"publisher_handle_err"`

	// Serialied XML bookmark to
	// restart at this vela-event
	Bookmark string `lua:"bookmark"`

	// Subscribed channel from which the vela-event was retrieved,
	// which may be different than the vela-event's channel
	SubscribedChannel string `lua:"subscribed_channel"`
}

type channelWatcher struct {
	subscription ListenerHandle
	callback     *LogEventCallbackWrapper
	bookmark     BookmarkHandle
}

// Watches one or more vela-event log channels
// and publishes events and errors to Go
// channels
type WinLogWatcher struct {
	errChan   chan error
	eventChan chan *WinLogEvent

	renderContext SysRenderContext

	watches  *sync.Map
	shutdown chan interface{}

	// Optionally render localized fields. EvtFormatMessage() is slow, so
	// skipping these fields provides a big speedup.
	RenderKeywords bool
	RenderMessage  bool
	RenderLevel    bool
	RenderTask     bool
	RenderProvider bool
	RenderOpcode   bool
	RenderChannel  bool
	RenderId       bool
}

type SysRenderContext uint64
type ListenerHandle uint64
type PublisherHandle uint64
type EventHandle uint64
type BookmarkHandle uint64

type LogEventCallback interface {
	PublishError(error)
	PublishEvent(EventHandle, string)
}

type LogEventCallbackWrapper struct {
	callback          LogEventCallback
	subscribedChannel string
}

func (xd *XmlEvent) ok() bool {
	return xd.err == nil
}

func (xd *XmlEvent) Bytes() []byte {
	if !xd.ok() {
		return []byte("{}")
	}

	buff := kind.NewJsonEncoder()
	buff.Tab("")
	buff.KV("xml_space", xd.XMLName.Space)
	buff.KV("xml_local", xd.XMLName.Local)
	buff.KV("xmlns", xd.Xmlns)
	buff.KV("text", xd.Text)

	buff.KV("event_text", xd.EvData.Text)
	buff.Arr("event_data")
	for _, item := range xd.EvData.Data {
		buff.KV(item.Name, item.Text)
	}
	buff.End("]}")

	return buff.Bytes()
}

func (xd *XmlEvent) String() string {
	return auxlib2.B2S(xd.Bytes())
}

func (evt *WinLogEvent) Field(key string) string {
	switch key {
	case "event_id":
		return auxlib2.ToString(evt.EventId)
	case "op_code":
		return auxlib2.ToString(evt.OpcodeText)
	case "ctime":
		return auxlib2.ToString(evt.Created)
	case "record_id":
		return auxlib2.ToString(evt.RecordId)
	case "xml":
		return evt.XmlText
	case "channel":
		return evt.Channel
	}

	return ""
}

func (evt *WinLogEvent) ToLValue() lua.LValue {
	return lua.NewAnyData(evt)
}
