# `_fixture` slice

A built-in smoke slice that exercises the whole pipeline (collect → record → evaluate
→ align → render) without touching any cloud provider. Used by the test suite and as a
live demo: `fr20x run-slice slices/_fixture --provider fixture --run-id demo-1`.
Not a real control — see `slices/_TEMPLATE/` to build a real one.
