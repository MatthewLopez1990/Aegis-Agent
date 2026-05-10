# Examples

## Summarize My Project Safely

```bash
PYTHONPATH=src python3 -m aegis.cli.main task submit "Summarize my project safely" --path .
```

## Create a Reusable Skill From a Workflow

Use `aegis.workflow_candidate` as the guarded starting point. Candidate workflows are disabled until reviewed.

## Connect a Mock ServiceNow Environment

```bash
PYTHONPATH=src python3 -m aegis.cli.main task submit "Read a ServiceNow ticket"
```

## Draft But Do Not Send a Message

```bash
PYTHONPATH=src python3 -m aegis.cli.main task submit "send message hello"
```

The task pauses in `waiting_approval`.

## Analyze Files Without Executing Untrusted Instructions

Put hostile text in a file and submit a summarize/read-only task. The file content is connector data, not instructions, and will be quarantined if suspicious.

## Require Approval Before Shell Execution

```bash
PYTHONPATH=src python3 -m aegis.cli.main task submit "run command: pwd"
```

## Inspect and Delete a Memory

```bash
PYTHONPATH=src python3 -m aegis.cli.main memory search project
PYTHONPATH=src python3 -m aegis.cli.main memory delete MEMORY_ID
```

## View an Action Receipt

```bash
PYTHONPATH=src python3 -m aegis.cli.main task status TASK_ID
PYTHONPATH=src python3 -m aegis.cli.main task evidence TASK_ID
```
