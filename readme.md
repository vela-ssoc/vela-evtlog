> windows 事件内容封装

内置字段:
- xml
- exdata &emsp; EventData对象
- provider_name
- event_id
- task
- op_code
- create_time
- record_id
- process_id, pid
- thread_id
- channel
- computer
- version
- render_field_err
- message
- level_text
- task_text
- op_code_text
- keywords
- channel_text
- id_text
- publish_err
- bookmark
- subscribe

```lua
    local w = win.evtlog{}
    
    w.pipe(function(ev)
        print(ev.exdata.name) --获取eventdata中的name字段
        print(ev.event_id)
    end)
    
    w.start()
```