# Testing

The public test surface uses only owned fixtures and synthetic evidence.

Current local verification:

- 34 generic Python unit tests pass.
- Native storage and generation integration passes.
- Resumable single-entry orchestration passes.
- Multi-entry orchestration and mechanical return-address callsite recovery pass.
- 15 of 16 native robustness cases pass.

The remaining robustness failure is the documented Windows exception-unwind behavior of the function-level Gum attach path. The instruction-probe path passes its corresponding exception case. This failure is retained as a visible capability limit; it is not renamed or treated as a passing result.

Target-specific tests and their output remain local and are not part of the public repository.
