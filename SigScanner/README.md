# SignatureScanner

A simple pattern scanner for IDA-style patterns (for internal and external)

**Internal Use:**

```cpp
SignatureScanner scanner = SignatureScanner(/*start address:*/(uintptr_t)GetModuleHandle(NULL)/*,end address: (optional)*/);
uintptr_t result = scanner.scan(/*byte pattern:*/"12 34 48 1f Ab cD EF ? ??"); // accepts both ? and ?? wildcards, uppercase and lowercase
printf("scan result: %llX", result);
```

**External Use:**

External scanning may be significantly slower than internal scanning on large applications

```cpp
HANDLE hProcess = OpenProcess(/*...*/);
SignatureScanner scanner = SignatureScanner scanner = SignatureScanner(/*process:*/hProcess, /*start address:*/(uintptr_t)GetModuleHandle(NULL)/*,end address: (optional)*/);
uintptr_t result = scanner.scanEx(/*byte pattern:*/"12 34 48 1f Ab cD EF ? ??"); // accepts both ? and ?? wildcards, uppercase and lowercase
printf("scan result: %llX", result);
```