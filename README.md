# assay

## ⚡ 30-Second Cold-Start Quick Reference

- **Runtime Prerequisites**: <FILL: each runtime this project needs and its minimum version>
- **Canonical Regression Shield Gate**:
  ```bash
  <FILL: the command that runs the whole test suite from this project root>
  ```

### 🛠️ AIKit Commands (run from the AIKit folder)
| Role | Command |
|---|---|
| Status, task and gates | `python aikit.py status assay` |
| Phase 4: every gate | `python aikit.py check assay` |
| Repair memory and map, then check | `python aikit.py fix assay` |
| Resume an interrupted task | `python aikit.py resume assay` |

## 📦 What's Inside

```text
assay/
├── .gitignore                <- transient AIKit state excluded
├── README.md
└── .aikit/                   <- this project's memory: record, ledger, decisions
```
