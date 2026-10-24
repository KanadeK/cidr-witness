# Contributing

Report a bug with the command, tool version and a small synthetic reproducer.
Do not attach confidential production inputs. The initial release is maintained
under a single-account commit policy; please use issues to propose changes.
No automated dependency-update or bot-commit workflow is enabled.

From a source checkout, Python 3.11 or newer:

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
python -m pip install ruff==0.14.1 build==1.3.0
python -m ruff check .
python -m ruff format --check .
python -m build
```

Include meaningful boundary tests and update documented limitations when behavior
changes. Keep the runtime dependency-free and reports deterministic.
