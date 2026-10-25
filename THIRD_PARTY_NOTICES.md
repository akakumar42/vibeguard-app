# Third-party notices

VibeGuard uses these open-source tools. They are run as separate programs; their source is not modified.
Their licences require these notices to stay with any copy of VibeGuard you share (source or Docker image).

| Tool | Version | Licence | Used for |
|---|---|---|---|
| jadx (skylot/jadx) | 1.5.6 | Apache-2.0 | Fast decompiler for Android apps |
| Semgrep | 1.182.0 | LGPL-2.1 | Running VibeGuard's scan rules |
| Gitleaks | 8.30.1 | MIT | Finding leaked keys |
| apksig (Android Open Source Project) | 9.3.3 | Apache-2.0 | Checking app signatures |
| rea-agents | 6.7.0 | MIT, Copyright (c) 2026 morluto | Inside the VibeGuard deep engine (not included in the Docker image) |

The full licence texts come with each tool: `LICENSE` and `NOTICE` in the jadx release, Semgrep's and Gitleaks'
`LICENSE` files, the Apache-2.0 header in apksig, and `tools/rea/node_modules/rea-agents/LICENSE` together with its
`THIRD_PARTY_NOTICES.md`.

## MIT licence (Gitleaks, rea-agents)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Apache-2.0 (jadx, apksig)

Licensed under the Apache License, Version 2.0: https://www.apache.org/licenses/LICENSE-2.0

## LGPL-2.1 (Semgrep)

Semgrep is used unmodified as a separate program. Licence: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html
