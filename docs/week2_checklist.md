# Week 2 Implementation Checklist

## Files needed from Week 1 (Member 4 tracks these)
| File | Owner | Needed for | Status |
|---|---|---|---|
| `docs/log_format.md` | Member 1 | Parser field definitions | [ ] |
| 10+ example entries with explanations | Member 1 | Parser tests | [ ] |
| `docs/regex_patterns.md` (4 regexes) | Member 2 | Detector implementation | [ ] |
| `docs/dfa_design.md` (diagrams + tables) | Member 2 | DFA implementation + slides | [ ] |
| `logs/sample_logs.txt` (~200 lines) | Member 3 | Running the scanner | [ ] |
| `tests/expected_anomalies.md` | Member 3 | Verifying detector output | [ ] |
| Thresholds (404 count/window, login count/window, business hours, UA list) | Member 2 | Detectors + severity | [ ] |
| Repo created, all members added as collaborators | Member 4 | Everything | [ ] |

## Week 2 tasks
- [ ] `src/scanner.py`: read file, parse lines, run 4 detectors, expose `scan_file(path)`
- [ ] Detectors return `models.Anomaly` with 1-based line numbers
- [ ] `src/report.py`: console + JSON report (done)
- [ ] `src/visualize.py`: chart (done)
- [ ] `src/main.py`: CLI (done)
- [ ] Compare scanner output with `tests/expected_anomalies.md`; record detection rate / false positives
- [ ] README run instructions verified on a clean clone
- [ ] Slides: mini SIEM vs Splunk (`docs/slides.pptx`)
- [ ] Rehearse demo: `python src/main.py logs/sample_logs.txt`

## Final submission checks
- [ ] Source code, README (build/run), and test cases all in the repo
- [ ] Runs without errors on a fresh machine (`pip install -r requirements.txt`)
- [ ] Each member has meaningful commits from their own account
- [ ] No large last-minute commits; no generated junk (`__pycache__`) committed
