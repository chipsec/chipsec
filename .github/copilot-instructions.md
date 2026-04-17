# Project general coding standards

## Testing
- Write unit tests for all new functionality
- Ensure existing tests pass before submitting changes
- Use mocks and stubs where appropriate to isolate units under test
- Strive for high test coverage, particularly for critical logic paths
- Use descriptive test names that clearly indicate the behavior being verified
- Add tests for edge cases and error conditions to ensure robustness

## Error Handling
- Always log errors with contextual information
- Exceptions are defined in the chipsec/library/exceptions module to avoid circular dependencies.