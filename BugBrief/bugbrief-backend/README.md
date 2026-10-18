# BugBrief backend

Turn a description, logs and screenshots into a structured, reproducible bug report, with privacy redaction, evidence checking and a repro score.

## CLI (Python 3.10+, no dependencies)
```
python -m bugbrief report --desc "Tap Pay and the page freezes every time" --logs samples/checkout-crash.log --style github
python -m bugbrief report --desc-file bug.txt --image shot.png --env version=2.4.1   # needs ANTHROPIC_API_KEY for the model draft
python -m bugbrief parse samples/checkout-crash.log     # find the error that matters
python -m bugbrief redact app.log --strict              # see what would be hidden
python -m bugbrief eval                                 # golden-set accuracy (add --live for the model check)
python -m bugbrief history | stats | export csv
```
Without ANTHROPIC_API_KEY you get an offline draft built from rules, clearly labelled.

## HTTP API
```
cp .env.example .env && docker build -t bugbrief . && docker run --env-file .env -p 8000:8000 -v bugbrief:/data bugbrief
curl -H "X-API-Key: $KEY" -X POST localhost:8000/v1/reports -H 'content-type: application/json' -d '{"description":"Tap Pay and it freezes"}'
```
Endpoints: `GET /healthz`, `POST|GET /v1/reports`, `GET|DELETE /v1/reports/{id}` (`?style=github|jira|plain|json`), `GET /v1/stats`, `POST /v1/redact`, `POST /v1/parse`.

## Tests: `python -m unittest discover -s tests` (26 tests)
Golden-set parity with the browser app (same `golden.json`), redaction, schema repair, grounding, scoring, duplicates, templates, the multimodal
request shape against a local fake API, retries and fallbacks, secrets never reaching the prompt, store and CLI end to end.

## Not yet verified
`bugbrief/api.py` compiles but was never run (FastAPI could not be installed where this was built). Run it and add `fastapi.testclient` tests before launch.
The live model path was tested only against a local fake server. Not built: accounts, billing, GitHub/Jira push, screenshot blurring.
