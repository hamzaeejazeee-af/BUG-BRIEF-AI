BugBrief - Made by Lubna Younas. Copyright (c) 2026 Lubna Younas. All rights reserved.

BugBrief - complete package
===========================
1. BugBrief-Roman-Urdu-Guide.pdf   Roman Urdu guide: what to do and how it works
2. BugBrief-presentation.pptx      11-slide presentation with speaker notes
3. bugbrief-app.html               The app as one file (interface and local checks work; Claude drafts only when opened via the link below)
4. bugbrief-backend/               Python backend: redaction, log parser, report logic, model layer, SQLite history, evals, CLI, API, 26 tests

Online links
  App:    https://claude.ai/artifact/VLD45cBv6xwTw1oCJvpJ4Y
  Report: https://claude.ai/code/artifact/e4c735fd-4bcf-4946-9c53-ca532d330a6c

Notes
- Backend tests: python -m unittest discover -s tests   (Python 3.10+, no extra packages needed)
- The web API file (bugbrief/api.py) has not been run yet.
- The 38 evaluation cases were written by the author and used to tune the rules, so 100% is optimistic.


--- UPDATE: running outside Claude ---
See HOW-TO-RUN.txt. An "AI Setup" button lets this page use a free Groq key (or Grok/xAI, paid, or Ollama) when opened as a normal file.
