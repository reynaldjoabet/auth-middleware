## Exception (Checked Exceptions)
Standard exceptions (that do not inherit from `RuntimeException`) are meant to represent `anticipatable`, `recoverable` conditions that happen outside the program's immediate control.
- Concept: "This is a risky operation (like reading a file or making a network request), and the caller needs to have a backup plan if it fails."
- Examples: `IOException` (file missing), `SQLException` (database rejected query), `TimeoutException`.
- Compiler Enforcement (in Java): Java enforces a strict rule: if a method can throw a checked exception, it must either catch it in a `try/catch` block, or declare it in the method signature using `throws`. The compiler will fail if you ignore it.

## RuntimeException (Unchecked Exceptions)
Runtime exceptions are meant to represent programming errors or unrecoverable logic failures.
- Concept: "This shouldn't happen if the code was written correctly. It's a bug, and the program should probably crash so the developer can fix it."
- Examples: `NullPointerException`, `IndexOutOfBoundsException`, `IllegalArgumentException`.
- Compiler Enforcement: The compiler does not force you to catch or declare them. It assumes that forcing developers to wrap every single array access or object reference in a try/catch block would make the language unusable

`Scala completely eliminates checked exceptions`.

In Scala, the compiler treats all exceptions—whether they are `Exception` or `RuntimeException`—as unchecked. The Scala compiler will never force you to write a `catch` block or declare a `throws` signature (unless you are specifically using the `@throws` annotation to maintain Java interoperability).

- `Extend RuntimeException` for your domain errors (like the AppError enum example). This is the standard idiom in modern Scala. It signals that this is a standard application logic error.

- `Extend Exception` almost never, unless you are writing a library that heavily interoperates with Java and you explicitly want Java callers to be forced to handle your specific exception.