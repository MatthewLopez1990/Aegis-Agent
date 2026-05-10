# Tools

Aegis has a governed tool catalog with 47+ entries:

- `calculator`
- `web_search`
- `http_request`
- `browser`
- `file_read`
- `file_write`
- `shell`
- `memory_store`
- `memory_recall`
- `vision_analyze`
- `image_generate`
- `tts`
- `voice_transcribe`
- `video_analyze`
- `subagent_delegate`
- `mcp_call`
- Web extraction, browser click/fill/screenshot/table extraction.
- Code execution, Python REPL, Git/GitHub, database, calendar, email, contacts.
- Documents, spreadsheets, PDF, archives, image edit, embeddings/vector index.
- Webhook/REST/RSS, price monitor, weather, maps, translation, summarizer.
- Patch application, package/container/SSH/Docker execution, terminal backend selection.
- Cron scheduling, Kanban creation, voice record, meeting summary, trajectory generation/compression.

Every tool has permission, risk, schema, and approval metadata. High-risk tools return approval-required results unless approved through policy. Tool outputs are audited and kept behind connector/tool taint boundaries.
