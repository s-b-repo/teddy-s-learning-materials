# questions.py
# Modular question bank for the C++ reverse-engineering quiz app.

from typing import List, Dict, Callable

def ci_equals(expected: str) -> Callable[[str], bool]:
    expected_norm = expected.strip().lower()
    def check(given: str) -> bool:
        return given.strip().lower() == expected_norm
    return check

def contains(expected_sub: str) -> Callable[[str], bool]:
    expected_sub_norm = expected_sub.strip().lower()
    def check(given: str) -> bool:
        return expected_sub_norm in given.strip().lower()
    return check

QUESTIONS: List[Dict] = [
    {
        "id": 1,
        "type": "mcq",
        "prompt": "Which of these is the correct command to compile a C++ file named main.cpp to an executable called main using g++?",
        "choices": ["g++ main.cpp -o main", "gcc main.cpp -o main", "clang main -o main", "g++ -run main.cpp"],
        "answer": 0,
        "hint": "g++ is the GNU C++ compiler; -o sets the output filename."
    },
    {
        "id": 2,
        "type": "mcq",
        "prompt": "What is the typical file format produced when compiling for Linux (x86_64)?",
        "choices": ["PE", "ELF", "Mach-O", "APK"],
        "answer": 1,
        "hint": "Executable and Linkable Format."
    },
    {
        "id": 3,
        "type": "text",
        "prompt": "Given this C++ snippet, what is the printed output?\n\n#include <iostream>\nint main(){ int x = 5; std::cout << ++x << std::endl; }\n\nAnswer with the exact printed line.",
        "answer": ci_equals("6"),
        "hint": "Pre-increment increases before printing."
    },
    {
        "id": 4,
        "type": "mcq",
        "prompt": "Which tool is commonly used to inspect assembly of an ELF binary?",
        "choices": ["objdump -d", "notepad", "photoshop", "ls -l"],
        "answer": 0,
        "hint": "GNU binutils contains objdump."
    },
    {
        "id": 5,
        "type": "text",
        "prompt": "Name one standard calling convention on x86_64 Linux used by C/C++ functions (short name).",
        "answer": contains("sysv"),
        "hint": "Look for System V AMD64 ABI."
    },
    {
        "id": 6,
        "type": "mcq",
        "prompt": "In reverse engineering, what does 'string references' help identify inside a binary?",
        "choices": ["Possible input/output messages", "Compilation flags", "Source file names only", "Network topology"],
        "answer": 0,
        "hint": "Strings often reveal UI, error messages, or protocol details."
    },
    {
        "id": 7,
        "type": "text",
        "prompt": "What C++ keyword marks a function as not modifying the object (const correctness)?",
        "answer": ci_equals("const"),
        "hint": "It's the same keyword used for constant variables."
    },
    {
        "id": 8,
        "type": "mcq",
        "prompt": "Which compiler optimization level will inline more aggressively?",
        "choices": ["-O0", "-O1", "-O2", "-O3"],
        "answer": 3,
        "hint": "Higher O numbers generally increase optimization aggressiveness."
    },
    {
        "id": 9,
        "type": "text",
        "prompt": "If you see a pattern of 'push rbp; mov rbp, rsp' in assembly, what C/C++ construct is this likely part of?",
        "answer": contains("function prologue"),
        "hint": "This sets up a stack frame for a function."
    },
    {
        "id": 10,
        "type": "mcq",
        "prompt": "Which header declares std::string in C++?",
        "choices": ["<vector>", "<string>", "<cstring>", "<iostream>"],
        "answer": 1,
        "hint": "std::string lives in a dedicated header."
    },
    {
        "id": 11,
        "type": "text",
        "prompt": "Given compiled binary with stripped symbols, what is one method to identify functions? Provide one short keyword answer.",
        "answer": contains("strings"),
        "hint": "Other methods include pattern recognition and heuristics; answer 'strings' is acceptable here."
    },
    {
        "id": 12,
        "type": "mcq",
        "prompt": "Which register typically stores the return value for integer functions on x86_64 Linux?",
        "choices": ["rax", "rbx", "rcx", "r12"],
        "answer": 0,
        "hint": "The low 64-bit register rax holds integer return values."
    },
    {
    "id": 13,
    "type": "mcq",
    "prompt": "Which g++ flag includes debugging symbols in the produced binary?",
    "choices": ["-g", "-s", "-O2", "-Wall"],
    "answer": 0,
    "hint": "Debug symbols allow source-level debugging with gdb."
},
{
    "id": 14,
    "type": "text",
    "prompt": "What tool is commonly used to step through program execution at the assembly level on Linux (short name)?",
    "answer": ci_equals("gdb"),
    "hint": "GNU Debugger."
},
{
    "id": 15,
    "type": "mcq",
    "prompt": "What section of an ELF binary typically contains executable code?",
    "choices": [".data", ".bss", ".text", ".rodata"],
    "answer": 2,
    "hint": "Executable instructions live in the code section."
},
{
    "id": 16,
    "type": "text",
    "prompt": "Which C++ feature allows a function to have the same name but different parameter lists (one short word)?",
    "answer": ci_equals("overloading"),
    "hint": "Common in constructors and operators."
},
{
    "id": 17,
    "type": "mcq",
    "prompt": "Which instruction sequence would likely indicate a tail call optimization in assembly?",
    "choices": ["call func; ret", "jmp func", "push rbp; mov rbp, rsp", "mov eax, 0; ret"],
    "answer": 1,
    "hint": "Tail calls often replace call+ret with a jump."
},
{
    "id": 18,
    "type": "text",
    "prompt": "Name one dynamic analysis technique often used in reverse engineering (short phrase).",
    "answer": contains("debug"),
    "hint": "Dynamic techniques include debugging, tracing, or fuzzing; 'debug' is acceptable."
},
{
    "id": 19,
    "type": "mcq",
    "prompt": "When compiling with -fno-rtti, which C++ feature is disabled?",
    "choices": ["Exceptions", "Run-time type information", "Inline functions", "Templates"],
    "answer": 1,
    "hint": "RTTI supports typeid and dynamic_cast."
},
{
    "id": 20,
    "type": "text",
    "prompt": "What short keyword identifies a function that cannot be overridden in a derived class in C++11 and later?",
    "answer": ci_equals("final"),
    "hint": "Used in method declarations or on classes."
},
{
    "id": 21,
    "type": "mcq",
    "prompt": "Which utility shows linked shared library dependencies of an ELF executable?",
    "choices": ["ldd", "nm", "strip", "readelf -S"],
    "answer": 0,
    "hint": "Run it on the binary to list needed shared objects."
},
{
    "id": 22,
    "type": "text",
    "prompt": "In x86_64 calling conventions on Linux, which registers are caller-saved (one short example, lower-case)?",
    "answer": contains("rax"),
    "hint": "Caller-saved registers include rax, rcx, rdx, rsi, rdi, r8-r11."
},
{
    "id": 23,
    "type": "mcq",
    "prompt": "Which symbol table tool lists symbols and their addresses from an object or binary?",
    "choices": ["objdump -d", "nm", "strings", "file"],
    "answer": 1,
    "hint": "nm prints symbol names and sizes from object files."
},
{
    "id": 24,
    "type": "text",
    "prompt": "When reverse-engineering a C++ binary, what short keyword describes automatically-generated functions like constructors and destructors (one word)?",
    "answer": contains("synthetic"),
    "hint": "Also acceptable: 'compiler-generated' as a descriptive phrase."
},
{
    "id": 25,
    "type": "mcq",
    "prompt": "Which g++ flag strips symbol information from the binary?",
    "choices": ["-g", "-s", "-O3", "-static"],
    "answer": 1,
    "hint": "Stripping removes debug and symbol tables."
},
{
    "id": 26,
    "type": "text",
    "prompt": "What short name is given to the relocation and symbol resolution performed at program load time for shared libraries?",
    "answer": ci_equals("dynamic linking"),
    "hint": "Opposite of static linking."
},
{
    "id": 27,
    "type": "mcq",
    "prompt": "Which command shows the section headers of an ELF file?",
    "choices": ["readelf -S", "objdump -t", "ldconfig", "nm -C"],
    "answer": 0,
    "hint": "readelf prints ELF-specific information including sections."
},
{
    "id": 28,
    "type": "text",
    "prompt": "What C++11 keyword introduces a lambda expression (short token)?",
    "answer": ci_equals("[]"),
    "hint": "Lambdas begin with capture brackets."
},
{
    "id": 29,
    "type": "mcq",
    "prompt": "Which of these is a typical symptom of aggressive inlining when inspecting disassembly?",
    "choices": ["Long consecutive instruction sequences from one source call", "Presence of many relocation entries", "Large .rodata section", "Multiple .eh_frame sections"],
    "answer": 0,
    "hint": "Inlining embeds callees into caller bodies."
},
{
    "id": 30,
    "type": "text",
    "prompt": "Name a short keyword for the table that maps function names to addresses used by dynamic linking (one word).",
    "answer": contains("plt"),
    "hint": "Procedure Linkage Table; 'plt' is acceptable."
},
{
    "id": 31,
    "type": "mcq",
    "prompt": "What does ASLR stand for in executable security?",
    "choices": ["Address Space Layout Randomization", "Automatic Stack Limit Removal", "Application Symbol Lookup Routine", "Advanced Security Linker Rights"],
    "answer": 0,
    "hint": "It randomizes memory layout to hinder exploitation."
},
{
    "id": 32,
    "type": "text",
    "prompt": "Give one short name of a disassembler often used for binary analysis (lower-case).",
    "answer": contains("radare"),
    "hint": "Acceptable examples include 'radare', 'ghidra', or 'ida'."
},
{
    "id": 33,
    "type": "mcq",
    "prompt": "Which compiler flag enables all common warnings in g++?",
    "choices": ["-Wall", "-Werror", "-Wextra", "-pedantic"],
    "answer": 0,
    "hint": "-Wall turns on a broad set of warnings."
},
{
    "id": 34,
    "type": "text",
    "prompt": "What one-word term describes code emitted by the compiler to support exceptions and stack unwinding?",
    "answer": contains("eh"),
    "hint": "Related terms: 'eh_frame', 'exception handling'."
},
{
    "id": 35,
    "type": "mcq",
    "prompt": "Which of these indicates a function pointer type in C++?",
    "choices": ["int (*)(int)", "int& (int)", "int { }", "int <int>"],
    "answer": 0,
    "hint": "Function pointer syntax uses parentheses and asterisk."
},
{
    "id": 36,
    "type": "text",
    "prompt": "When reading stripped binary disassembly, what short keyword describes heuristics that detect likely function boundaries (one word)?",
    "answer": contains("heuristics"),
    "hint": "Also acceptable: 'analysis' or 'heuristic'."
},
{
    "id": 37,
    "type": "text",
    "prompt": "Write the exact printed output of this C++ program (single line):\n\n#include <iostream>\nint add(int a, int b){ return a + b; }\nint main(){ std::cout << add(2, 3) << std::endl; }\n\nAnswer with the exact printed line.",
    "answer": ci_equals("5"),
    "hint": "Simple function returning the sum."
},
{
    "id": 38,
    "type": "mcq",
    "prompt": "Which of these function signatures declares a function that takes a const reference to a std::string and returns its length as size_t?",
    "choices": ["size_t len(const std::string &s)", "int len(std::string s) const", "void len(std::string &s)", "size_t len(std::string *s) const"],
    "answer": 0,
    "hint": "Use const reference parameter and size_t return type."
},
{
    "id": 39,
    "type": "text",
    "prompt": "Provide the one-word name of the algorithmic approach that splits a problem into smaller subproblems and combines results (lower-case).",
    "answer": ci_equals("divideandconquer"),
    "hint": "Commonly demonstrated by mergesort and quicksort; accept 'divideandconquer'."
},
{
    "id": 40,
    "type": "mcq",
    "prompt": "Which loop will always execute its body at least once in C++?",
    "choices": ["for", "while", "do-while", "range-based for"],
    "answer": 2,
    "hint": "do-while checks the condition after the body."
},
{
    "id": 41,
    "type": "text",
    "prompt": "Given this function prototype: int factorial(int n); give the exact output when calling factorial(4) for a typical recursive implementation that returns 1 for n==0. Answer with the exact number.",
    "answer": ci_equals("24"),
    "hint": "4! = 4*3*2*1."
},
{
    "id": 42,
    "type": "mcq",
    "prompt": "Which C++ container provides constant-time random access to elements by index?",
    "choices": ["std::list", "std::vector", "std::map", "std::forward_list"],
    "answer": 1,
    "hint": "vector stores elements contiguously."
},
{
    "id": 43,
    "type": "text",
    "prompt": "Write a one-word answer naming a common hashing container in C++ that maps keys to values (lower-case).",
    "answer": contains("unordered_map"),
    "hint": "Standard unordered associative container introduced in C++11."
},
{
    "id": 44,
    "type": "mcq",
    "prompt": "Which of these function qualifiers indicates the method does not modify member variables (when applied to a member function)?",
    "choices": ["virtual", "static", "const", "override"],
    "answer": 2,
    "hint": "const after the signature marks immutability."
},
{
    "id": 45,
    "type": "text",
    "prompt": "Provide the exact printed output (single line) of this C++ snippet:\n\n#include <iostream>\nint main(){ for(int i=0;i<3;++i) std::cout << i << \" \"; }\n\nAnswer with the exact printed characters.",
    "answer": ci_equals("0 1 2 "),
    "hint": "Loop prints i and a space each iteration."
},
{
    "id": 46,
    "type": "mcq",
    "prompt": "Which algorithmic complexity class describes binary search on a sorted array of n elements?",
    "choices": ["O(n)", "O(log n)", "O(n log n)", "O(1)"],
    "answer": 1,
    "hint": "Binary search halves the search space each step."
},
{
    "id": 47,
    "type": "text",
    "prompt": "Name one basic string operation that returns the number of characters in a std::string (one short token).",
    "answer": contains("size"),
    "hint": "Methods: size() or length(); 'size' is acceptable."
},
{
    "id": 48,
    "type": "text",
    "prompt": "Challenge: give a short single-line C++ function signature (no body) that takes a vector of ints by const reference and returns the maximum int found (use std::vector and int).",
    "answer": contains("int max(const std::vector<int> &v)"),
    "hint": "Return type int, parameter const std::vector<int> &v; exact spacing is flexible but content must match."
},
{
    "id": 49,
    "type": "mcq",
    "prompt": "What does OOM stand for in the context of a running program?",
    "choices": ["Out Of Memory", "Object Oriented Module", "Operational Output Mistake", "On-demand Memory"],
    "answer": 0,
    "hint": "Occurs when the system cannot allocate more memory for the process."
},
{
    "id": 50,
    "type": "text",
    "prompt": "Give one short keyword for a common function-family in C that can cause buffer overflow when used unsafely (lower-case).",
    "answer": contains("strcpy"),
    "hint": "Unsafe string copy functions are classic sources of overflows."
},
{
    "id": 51,
    "type": "mcq",
    "prompt": "Which condition best describes a buffer underflow?",
    "choices": ["Reading before the start of an allocated buffer", "Writing past the end of a buffer", "Allocating zero bytes", "Exhausting the heap"],
    "answer": 0,
    "hint": "Underflow reads memory before the buffer base address."
},
{
    "id": 52,
    "type": "text",
    "prompt": "Name one common mitigation that prevents simple stack buffer overflows (short phrase).",
    "answer": contains("stack canary"),
    "hint": "Other answers acceptable: 'stack canaries', 'canary'."
},
{
    "id": 53,
    "type": "mcq",
    "prompt": "Which operating system feature randomizes base addresses of stacks and libraries to make exploitation harder?",
    "choices": ["ASLR", "NX", "DEP", "PIE"],
    "answer": 0,
    "hint": "Address Space Layout Randomization."
},
{
    "id": 54,
    "type": "text",
    "prompt": "Give a one-word name for the protection that marks memory pages as non-executable (lower-case).",
    "answer": ci_equals("nx"),
    "hint": "Also called DEP (Data Execution Prevention) on some platforms."
},
{
    "id": 55,
    "type": "mcq",
    "prompt": "Which allocator-related issue can directly lead to OOM if not handled?",
    "choices": ["Memory leak", "Function inlining", "Constant folding", "Dead code elimination"],
    "answer": 0,
    "hint": "Leaked allocations accumulate and exhaust available memory."
},
{
    "id": 56,
    "type": "text",
    "prompt": "What short term describes code that frees memory more than once for the same pointer (one word)?",
    "answer": ci_equals("doublefree"),
    "hint": "Double-free bugs corrupt allocator metadata and cause instability."
},
{
    "id": 57,
    "type": "mcq",
    "prompt": "Which tool helps detect memory errors like leaks, use-after-free, and invalid accesses during runtime?",
    "choices": ["valgrind", "gcc", "make", "tar"],
    "answer": 0,
    "hint": "Valgrind's memcheck catches many dynamic memory issues."
},
{
    "id": 58,
    "type": "text",
    "prompt": "Give a short one-line defensive coding practice to reduce buffer overflow risk (use plain text).",
    "answer": contains("bounds check"),
    "hint": "Examples: 'check lengths before copying' or 'perform bounds checks'."
},
{
    "id": 59,
    "type": "mcq",
    "prompt": "Which C++ facility reduces manual heap management and helps avoid many memory leaks?",
    "choices": ["raw new/delete everywhere", "smart pointers like std::unique_ptr and std::shared_ptr", "using global malloc", "manually tracking addresses in arrays"],
    "answer": 1,
    "hint": "RAII and smart pointers automate lifetime management."
},
{
    "id": 60,
    "type": "text",
    "prompt": "Name one brief symptom that might indicate an OOM condition on Linux when a program is killed by the kernel (short phrase).",
    "answer": contains("oom killer"),
    "hint": "Look for 'Out of memory' logs or the kernel OOM killer terminating processes."
},
{
    "id": 61,
    "type": "mcq",
    "prompt": "Which of the following code snippets most likely causes an Out-Of-Memory (OOM) by unbounded growth?",
    "choices": [
        "std::vector<int> v; while(true) v.push_back(1);",
        "int x = 0; for(int i=0;i<10;++i) x += i;",
        "std::array<int, 100> a; a[0] = 1;",
        "std::string s = \"hello\"; s.size();"
    ],
    "answer": 0,
    "hint": "Unbounded allocation in a loop without limits can exhaust memory."
},
{
    "id": 62,
    "type": "mcq",
    "prompt": "Which snippet is most indicative of a stack buffer overflow risk?",
    "choices": [
        "char buf[8]; strcpy(buf, user_input);",
        "std::vector<char> buf(user_input.size()); memcpy(buf.data(), user_input.data(), user_input.size());",
        "auto p = std::make_unique<char[]>(len); read(fd, p.get(), len);",
        "std::string s = user_input; std::cout << s;"
    ],
    "answer": 0,
    "hint": "Fixed-size stack buffers combined with unsafe copy functions are classic overflow patterns."
},
{
    "id": 63,
    "type": "mcq",
    "prompt": "Which example best depicts a use-after-free vulnerability?",
    "choices": [
        "char *p = (char*)malloc(16); free(p); printf(\"%c\", p[0]);",
        "std::string s = \"abc\"; std::cout << s;",
        "int *a = new int[4]; a[0] = 1; delete[] a; a = nullptr;",
        "std::vector<int> v; v.push_back(1);"
    ],
    "answer": 0,
    "hint": "Accessing memory after free is a use-after-free issue."
},
{
    "id": 64,
    "type": "mcq",
    "prompt": "Which code most clearly demonstrates a double-free scenario?",
    "choices": [
        "char *p = (char*)malloc(8); free(p); free(p);",
        "std::unique_ptr<int> p(new int);",
        "std::vector<int> v; v.clear();",
        "int x = 0; delete &x;"
    ],
    "answer": 0,
    "hint": "Calling free/delete twice on the same pointer is a double-free."
},
{
    "id": 65,
    "type": "mcq",
    "prompt": "Which snippet suggests an integer overflow that can lead to unsafe allocations?",
    "choices": [
        "size_t size = n * sizeof(Item); void *p = malloc(size);",
        "int x = 1 + 1; std::cout << x;",
        "std::map<int,int> m; m[0] = 1;",
        "for(int i=0;i<10;i++) {}"
    ],
    "answer": 0,
    "hint": "Multiplying counts by element size without checking can overflow size_t and cause under-allocation."
},
{
    "id": 66,
    "type": "mcq",
    "prompt": "Which example most likely allows buffer underflow (reading before buffer start)?",
    "choices": [
        "char buf[10]; char c = buf[-1];",
        "char buf[10]; buf[0] = 'a';",
        "std::string s; s.push_back('a');",
        "int arr[3]; arr[2] = 0;"
    ],
    "answer": 0,
    "hint": "Indexing with a negative offset reads before the buffer base."
},
{
    "id": 67,
    "type": "mcq",
    "prompt": "Which snippet is a likely cause of uncontrolled recursion leading to stack exhaustion?",
    "choices": [
        "void f(){ f(); } int main(){ f(); }",
        "int sum(int n){ return n>0 ? n + sum(n-1) : 0; }",
        "int main(){ return 0; }",
        "void g(int n){ if(n>0) g(n-1); }"
    ],
    "answer": 0,
    "hint": "Infinite recursion without a base case quickly exhausts stack space."
},
{
    "id": 68,
    "type": "mcq",
    "prompt": "Which example most clearly demonstrates missing bounds checks before a copy into a heap buffer?",
    "choices": [
        "char *b = (char*)malloc(len); memcpy(b, src, src_len);",
        "std::vector<char> b(len); memcpy(b.data(), src, std::min(len, src_len));",
        "std::string s = \"ok\";",
        "auto p = std::make_unique<char[]>(len);"
    ],
    "answer": 0,
    "hint": "Copying more bytes than the allocated len without checking causes heap overflow."
},
{
    "id": 69,
    "type": "mcq",
    "prompt": "Which code is an example of insufficient input validation that could lead to many exploit classes (choose best)?",
    "choices": [
        "read(fd, buf, n); // no check that n is reasonable or validated",
        "if(n<0) return; memcpy(buf, src, n);",
        "std::vector<int> v(n);",
        "int x = atoi(s.c_str());"
    ],
    "answer": 0,
    "hint": "Unvalidated lengths or counts in I/O are a common root cause for overflow, OOM, and other faults."
},
{
    "id": 70,
    "type": "text",
    "prompt": "Explain in one short sentence why unchecked allocations using untrusted size values can cause OOM or security problems.",
    "answer": contains("untrusted"),
    "hint": "Mention untrusted or attacker-controlled size leading to resource exhaustion or truncated allocations."
},
{
    "id": 71,
    "type": "mcq",
    "prompt": "Which mitigation is most directly effective against many heap-based overflow exploits?",
    "choices": [
        "Use of safe allocation checks, bounds checks, and high-level containers",
        "Removing all comments from source code",
        "Compiling with -O3 only",
        "Using globals everywhere"
    ],
    "answer": 0,
    "hint": "Proper checks and safer abstractions reduce heap overflow risks."
},
{
    "id": 72,
    "type": "text",
    "prompt": "Give one short defensive coding rule to avoid use-after-free bugs (plain text, short).",
    "answer": contains("set pointer to null"),
    "hint": "Common practice: set freed pointers to nullptr and avoid dangling references."
},
{
    "id": 73,
    "type": "mcq",
    "prompt": "Which snippet most likely leads to OOM by repeatedly allocating without freeing?",
    "choices": [
        "while(true){ void *p = malloc(1024); /* no free */ }",
        "int a = 0; a++;",
        "char buf[16]; strncpy(buf, src, 16);",
        "std::vector<int> v; v.reserve(10);"
    ],
    "answer": 0,
    "hint": "Unbounded allocations with no corresponding free exhaust heap memory."
},
{
    "id": 74,
    "type": "mcq",
    "prompt": "Which code most likely demonstrates an integer overflow that could cause a wrong, too-small allocation?",
    "choices": [
        "size_t sz = n * sizeof(Item); ptr = malloc(sz);",
        "int x = 2 + 2;",
        "std::string s = \"ok\";",
        "auto v = std::vector<int>(10);"
    ],
    "answer": 0,
    "hint": "Multiplying a large count by element size can overflow size_t and under-allocate."
},
{
    "id": 75,
    "type": "mcq",
    "prompt": "Which snippet best shows uncontrolled recursion that may exhaust memory or stack?",
    "choices": [
        "void recurse(){ recurse(); }",
        "for(int i=0;i<10;i++){}",
        "int x = 1; x++;",
        "std::map<int,int> m;"
    ],
    "answer": 0,
    "hint": "Infinite or very deep recursion uses stack frames until exhaustion."
},
{
    "id": 76,
    "type": "mcq",
    "prompt": "Which example most clearly allows a heap buffer overflow by copying more data than allocated?",
    "choices": [
        "char *p = (char*)malloc(len); memcpy(p, src, src_len);",
        "std::vector<char> v(len); memcpy(v.data(), src, std::min(len, src_len));",
        "std::string s = src.substr(0, len);",
        "auto p = std::make_unique<char[]>(len); memcpy(p.get(), src, len);"
    ],
    "answer": 0,
    "hint": "Copying src_len bytes into p when src_len may exceed len is unsafe."
},
{
    "id": 77,
    "type": "mcq",
    "prompt": "Which code pattern most strongly indicates a use-after-free risk?",
    "choices": [
        "char *p = (char*)malloc(8); free(p); printf(\"%c\", p[0]);",
        "std::unique_ptr<int> p(new int(1));",
        "int x = 0; x = x + 1;",
        "void f(){}"
    ],
    "answer": 0,
    "hint": "Accessing p after free is classic UAF."
},
{
    "id": 78,
    "type": "mcq",
    "prompt": "Which snippet is most indicative of a stack buffer overflow possibility?",
    "choices": [
        "char buf[32]; gets(buf);",
        "std::vector<char> buf(32); read(fd, buf.data(), 32);",
        "auto s = std::string(\"hello\");",
        "int main(){ return 0; }"
    ],
    "answer": 0,
    "hint": "Unsafe input into fixed-size stack buffer risks overflow."
},
{
    "id": 79,
    "type": "mcq",
    "prompt": "Which example is a likely cause of double-free or invalid-free?",
    "choices": [
        "int *p = (int*)malloc(4*sizeof(int)); free(p); free(p);",
        "std::vector<int> v; v.push_back(1);",
        "int x = 5; delete &x;",
        "auto p = std::make_unique<int[]>(4);"
    ],
    "answer": 0,
    "hint": "Calling free twice on same pointer leads to double-free."
},
{
    "id": 80,
    "type": "mcq",
    "prompt": "Which snippet demonstrates missing bounds checks that can enable many exploit types?",
    "choices": [
        "int readn(int n){ char *b = (char*)malloc(n); read(fd, b, n); }",
        "if(n<0) return; char *b = (char*)malloc(n);",
        "std::string s; getline(cin, s);",
        "auto v = std::vector<int>(n);"
    ],
    "answer": 0,
    "hint": "Using n directly for allocation and I/O without validation is risky."
},
{
    "id": 81,
    "type": "mcq",
    "prompt": "Which of these best shows a pattern that could allow integer-to-pointer truncation problems on 32/64-bit mismatches?",
    "choices": [
        "uintptr_t p = (uintptr_t)some_large_value; void *q = (void*)p;",
        "int x = 1; int y = 2;",
        "std::vector<int> v(10);",
        "char buf[8];"
    ],
    "answer": 0,
    "hint": "Casting large integers to pointer-sized types without checks can truncate addresses."
},
{
    "id": 82,
    "type": "text",
    "prompt": "Write one short defensive rule to prevent integer-overflow-based allocation bugs (plain text).",
    "answer": contains("overflow"),
    "hint": "Answer should mention checking for overflow, validating multiplications, or using safe math helpers."
},
{
    "id": 83,
    "type": "mcq",
    "prompt": "Which mitigation most directly reduces the impact of buffer overflows in production binaries?",
    "choices": [
        "Enable stack canaries, NX, ASLR, and compile-time bounds checking where possible",
        "Remove all asserts from code",
        "Increase optimization level to -O3",
        "Use shorter variable names"
    ],
    "answer": 0,
    "hint": "Multiple memory protections together make exploitation harder."
},
{
    "id": 84,
    "type": "text",
    "prompt": "Give one short phrase describing why validating input lengths and types is critical to avoid exploit classes (plain text).",
    "answer": contains("validate"),
    "hint": "Mention that validation prevents uncontrolled sizes, unexpected values, and resource exhaustion."
},
{
    "id": 85,
    "type": "mcq",
    "prompt": "Which Ghidra feature displays a function's decompiled C-like pseudocode?",
    "choices": ["Listing window", "Decompiler window", "Symbol tree", "Console"],
    "answer": 1,
    "hint": "The decompiler produces readable C-like output from assembly."
},
{
    "id": 86,
    "type": "text",
    "prompt": "What short command or action in Ghidra renames a local variable or function symbol (one word, lower-case)?",
    "answer": ci_equals("rename"),
    "hint": "You can right-click and choose rename or press the rename hotkey."
},
{
    "id": 87,
    "type": "mcq",
    "prompt": "Which Ghidra view shows raw assembly instructions alongside addresses and bytes?",
    "choices": ["Decompiler", "Listing", "Symbol tree", "Data Type Manager"],
    "answer": 1,
    "hint": "The Listing shows disassembly, bytes, and applied labels."
},
{
    "id": 88,
    "type": "text",
    "prompt": "Give one short name of the table in Ghidra that maps imported functions from shared libraries (one token).",
    "answer": contains("imports"),
    "hint": "Look for entries representing external library calls."
},
{
    "id": 89,
    "type": "mcq",
    "prompt": "Which action in Ghidra helps identify cross-references to a function or string?",
    "choices": ["Find References", "Decompile All", "Export Program", "Create Project"],
    "answer": 0,
    "hint": "Finding references shows who calls or uses a symbol."
},
{
    "id": 90,
    "type": "text",
    "prompt": "What short token describes the Ghidra component where you edit or create data type definitions (one word)?",
    "answer": contains("datatype"),
    "hint": "It's named Data Type Manager in the UI; 'datatype' is acceptable."
},
{
    "id": 91,
    "type": "mcq",
    "prompt": "Which plugin or feature in Ghidra can help automatically recover function boundaries and apply analysis?",
    "choices": ["Auto-Analysis", "Script Manager", "Export", "Bookmarks"],
    "answer": 0,
    "hint": "Auto-analysis runs many analyzers to identify functions, strings, and types."
},
{
    "id": 92,
    "type": "text",
    "prompt": "Name one scripting language supported by Ghidra for writing automation scripts (lower-case).",
    "answer": contains("python"),
    "hint": "Ghidra supports Java and Jython/Python for scripting."
},
{
    "id": 93,
    "type": "mcq",
    "prompt": "Which Ghidra tool helps visualize function call relationships as a graph?",
    "choices": ["Function Graph", "Memory Map", "Decompiler", "Listing Window"],
    "answer": 0,
    "hint": "Function Graph shows callers and callees visually."
},
{
    "id": 94,
    "type": "text",
    "prompt": "Provide a short one-line reason why renaming functions and variables in Ghidra is useful during analysis (plain text).",
    "answer": contains("readability"),
    "hint": "Renaming improves readability and documents discovered semantics."
},
{
    "id": 95,
    "type": "mcq",
    "prompt": "Which Ghidra feature lets you run user-written analysis to modify the program database (e.g., add comments, types)?",
    "choices": ["Script Manager", "Bookmarks", "Symbol Tree", "Export Program"],
    "answer": 0,
    "hint": "Scripts automate repetitive analysis tasks via the Script Manager."
},
{
    "id": 96,
    "type": "text",
    "prompt": "When a decompiler output shows an opaque pointer type like 'undefined4 *', what short defensive step should you take to improve analysis (one short phrase)?",
    "answer": contains("define type"),
    "hint": "Create or apply proper data types and structures to improve decompilation."
},
  {
    "id": 97,
    "type": "text",
    "prompt": "In x86 assembly, what does the instruction 'mov eax, ebx' do in one short phrase (one token)?",
    "answer": contains("copy"),
    "hint": "mov copies data from the source operand to the destination operand."
  },
  {
    "id": 98,
    "type": "mcq",
    "prompt": "When reading Ghidra's Listing window, which column shows the raw assembly bytes for each instruction?",
    "choices": ["Bytes", "Mnemonic", "Label", "Comment"],
    "answer": 0,
    "hint": "The Bytes column displays the instruction encodings in hex."
  },
  {
    "id": 99,
    "type": "text",
    "prompt": "Name the common register that typically holds the return value in 32-bit x86 CDECL (one token).",
    "answer": contains("eax"),
    "hint": "On 32-bit x86, functions usually return values in the EAX register."
  },
  {
    "id": 100,
    "type": "mcq",
    "prompt": "Which Ghidra view shows a high-level C-like representation that helps map assembly to readable logic?",
    "choices": ["Decompiler", "Listing", "Function Graph", "Memory Map"],
    "answer": 0,
    "hint": "The Decompiler produces a C-like pseudo-code view of functions."
  },
  {
    "id": 101,
    "type": "text",
    "prompt": "Give a short step (three words) to follow when a decompiled variable is 'undefined4' to improve clarity.",
    "answer": contains("apply correct type"),
    "hint": "Define the variable's true type or structure in the Data Type Manager."
  },
  {
    "id": 102,
    "type": "mcq",
    "prompt": "Which pattern in the Listing often marks a function prolog in x86 (entry setup)?",
    "choices": ["push ebp; mov ebp, esp", "ret", "jmp", "int 0x80"],
    "answer": 0,
    "hint": "Function prologs typically save the old base pointer and set up a stack frame."
  },
  {
    "id": 103,
    "type": "text",
    "prompt": "Write one short token describing the action you take to see who calls a function in Ghidra (one token).",
    "answer": contains("xref"),
    "hint": "Use Find References or Show Xrefs to see callers and users."
  },
  {
    "id": 104,
    "type": "mcq",
    "prompt": "What is the safest first step before making edits or renames in a Ghidra project?",
    "choices": ["Create a snapshot", "Delete functions", "Export binary", "Run external debugger"],
    "answer": 0,
    "hint": "Take a snapshot or save a project backup so changes can be reverted."
  },
  {
    "id": 105,
    "type": "text",
    "prompt": "When you see 'call 0x401020' in assembly, what short phrase describes what you should do to understand it (two words)?",
    "answer": contains("follow call"),
    "hint": "Navigate to the target address or decompile the called function to inspect behavior."
  },
  {
    "id": 106,
    "type": "mcq",
    "prompt": "Which Ghidra feature helps convert a sequence of assembly instructions into named fields of a structure when reading data?",
    "choices": ["Struct Editor", "Script Manager", "Bookmarks", "Symbol Tree"],
    "answer": 0,
    "hint": "Use the Structure/Struct Editor in the Data Type Manager to model data layouts."
  },
  {
    "id": 107,
    "type": "text",
    "prompt": "Provide a one-line step (plain text) you should take when a function uses stack offsets like [ebp-0x8] frequently.",
    "answer": contains("create local variable"),
    "hint": "Define local variables at those offsets with appropriate types to clarify usage."
  },
  {
    "id": 108,
    "type": "mcq",
    "prompt": "Which tactic helps confirm the meaning of a magic constant found in code during reverse engineering?",
    "choices": ["Search for references", "Rename file", "Delete function", "Export listing"],
    "answer": 0,
    "hint": "Searching for references or related constants can reveal purpose or context."
  },
  {
    "id": 109,
    "type": "text",
    "prompt": "Step 1: You opened a function and see these two instructions at its start: 'push rbp' then 'mov rbp, rsp'. In one short phrase, what does this sequence establish (two words)?",
    "answer": contains("stack frame"),
    "hint": "This sets up the function's stack frame so locals and saved registers can be used."
  },
  {
    "id": 110,
    "type": "text",
    "prompt": "Step 2: The decompiler shows a local variable as 'undefined8 local_20'. What two-word action should you take to make subsequent reading clearer?",
    "answer": contains("assign type"),
    "hint": "Pick a reasonable type (pointer, int, struct) and apply it to the local variable."
  },
  {
    "id": 111,
    "type": "mcq",
    "prompt": "Step 3: You see 'mov rdi, rsi' in x86_64 assembly. Which plain intent best matches this instruction?",
    "choices": ["Copy register", "Start syscall", "Return value", "Push stack"],
    "answer": 0,
    "hint": "mov transfers data from source to destination register."
  },
  {
    "id": 112,
    "type": "text",
    "prompt": "Step 4: The function calls an imported routine 'strcmp'. In one token, what likely is being compared here?",
    "answer": contains("string"),
    "hint": "strcmp compares two C-style strings; look for pointers or buffers passed in."
  },
  {
    "id": 113,
    "type": "text",
    "prompt": "Step 5: Assembly shows 'lea rax, [rbp-0x30]'. What short token describes what LEA does here (one token)?",
    "answer": contains("address"),
    "hint": "LEA computes the effective address without performing a memory load."
  },
  {
    "id": 114,
    "type": "mcq",
    "prompt": "Step 6: You find 'call 0x401200' in a function. Which immediate next action best helps you understand what that call does?",
    "choices": ["Go to target", "Rename here", "Delete call", "Export binary"],
    "answer": 0,
    "hint": "Navigate to the called function or decompile it to inspect behavior."
  },
  {
    "id": 115,
    "type": "text",
    "prompt": "Step 7: At a call site you observe registers set like 'mov rdi, rbx' then 'mov rsi, 0x20' before calling. Give two words describing what those registers likely are (two words).",
    "answer": contains("function args"),
    "hint": "On x86_64, rdi/rsi/rdx/... commonly hold the first arguments to a function."
  },
  {
    "id": 116,
    "type": "mcq",
    "prompt": "Step 8: The decompiler returns 'if (strcmp(a, b) == 0)'. What is the condition checking?",
    "choices": ["Strings equal", "Strings different", "Buffer overflow", "Null pointer"],
    "answer": 0,
    "hint": "strcmp returns 0 when two strings match exactly."
  },
  {
    "id": 117,
    "type": "text",
    "prompt": "Step 9: You see repeated writes like 'mov QWORD PTR [rbp-0x40], rax' filling a buffer. Provide one token naming the risk you should check for (one token).",
    "answer": contains("overflow"),
    "hint": "Repeated writes into a fixed buffer can overflow if bounds aren't checked."
  },
  {
    "id": 118,
    "type": "text",
    "prompt": "Step 10: A decompiled expression shows 'buf[i] = input[j]'. What short two-word step helps confirm safe behavior before trusting this code?",
    "answer": contains("check bounds"),
    "hint": "Verify indices are checked against buffer sizes to avoid out-of-bounds writes."
  },
  {
    "id": 119,
    "type": "mcq",
    "prompt": "Step 11: The function returns an integer stored in RAX on x86_64. Which short label is most informative to rename the return value if it indicates success/failure?",
    "choices": ["status", "tmp", "v1", "junk"],
    "answer": 0,
    "hint": "Rename return values to 'status' or 'ret' to document meaning; 'tmp' is not descriptive."
  },
  {
    "id": 120,
    "type": "text",
    "prompt": "Step 12: You encounter a magic constant 0x1F4 used when allocating memory. Give one short phrase (two words) describing how to discover what size it represents in decimal.",
    "answer": contains("convert decimal"),
    "hint": "Translate the hex to decimal or inspect how that value is used (bytes, objects)."
  },
  {
    "id": 121,
    "type": "mcq",
    "prompt": "Step 13: A function checks 'if (eax < 0)'. Which behavior does this typically indicate about eax?",
    "choices": ["error code", "positive length", "pointer value", "random data"],
    "answer": 0,
    "hint": "Negative return values often signal error codes from calls."
  },
  {
    "id": 122,
    "type": "text",
    "prompt": "Step 14: You see 'xor eax, eax' before returning. In one short token what common action does this perform (one token)?",
    "answer": contains("zero"),
    "hint": "XOR a register with itself zeroes it efficiently, commonly used to return 0."
  },
  {
    "id": 123,
    "type": "text",
    "prompt": "Step 15: The code dereferences a pointer loaded from a global and then calls a function pointer. Provide one short phrase (two words) describing what you should do to understand this indirect call.",
    "answer": contains("resolve pointer"),
    "hint": "Find where the global is set or examine initialization code to find the actual function."
  },
  {
    "id": 124,
    "type": "mcq",
    "prompt": "Step 16: You want to find all places that pass a buffer to 'memcpy'. Which Ghidra action is best for that?",
    "choices": ["Find References", "Create Bookmark", "Export Program", "Run Script"],
    "answer": 0,
    "hint": "Find References/Xrefs shows all call sites for the function."
  },
  {
    "id": 125,
    "type": "text",
    "prompt": "Step 17: After renaming locals and applying types, the decompiler reads clearer. What one short phrase (two words) describes your next documentation step to help others?",
    "answer": contains("add comments"),
    "hint": "Annotate tricky logic with comments explaining assumptions and evidence."
  },
  {
    "id": 126,
    "type": "mcq",
    "prompt": "Step 18: To test a hypothesis about input causing a crash, which safe step should you take before running the program with crafted input?",
    "choices": ["Use debugger", "Delete files", "Rename binary", "Disable analysis"],
    "answer": 0,
    "hint": "Run under a debugger or in an isolated VM to observe behavior safely."
  },
  {
    "id": 127,
    "type": "text",
    "prompt": "Step 19: You reconstruct a short string built byte-by-byte in a loop. Give one short two-word step to verify its final value at runtime.",
    "answer": contains("print string"),
    "hint": "Log or print the buffer in a debugger or instrumented run to confirm contents."
  },
  {
    "id": 128,
    "type": "text",
    "prompt": "Step 20: You finished analyzing the function. Provide one short phrase (three words) describing how to package your findings for handoff.",
    "answer": contains("write analysis report"),
    "hint": "Include renamed symbols, types, control-flow notes, and reproducible steps to test behaviors."
  },
  {
    "id": 129,
    "type": "text",
    "prompt": "Step 1: You opened a function and see these two instructions at its start: 'push rbp' then 'mov rbp, rsp'. In one short phrase, what does this sequence establish (two words)?",
    "answer": contains("stack frame"),
    "hint": "This sets up the function's stack frame so locals and saved registers can be used."
  },
  {
    "id": 130,
    "type": "text",
    "prompt": "Step 2: The decompiler shows a local variable as 'undefined8 local_20'. What two-word action should you take to make subsequent reading clearer?",
    "answer": contains("assign type"),
    "hint": "Pick a reasonable type (pointer, int, struct) and apply it to the local variable."
  },
  {
    "id": 131,
    "type": "mcq",
    "prompt": "Step 3: You see 'mov rdi, rsi' in x86_64 assembly. Which plain intent best matches this instruction?",
    "choices": ["Copy register", "Start syscall", "Return value", "Push stack"],
    "answer": 0,
    "hint": "mov transfers data from source to destination register."
  },
  {
    "id": 132,
    "type": "text",
    "prompt": "Step 4: The function calls an imported routine 'strcmp'. In one token, what likely is being compared here?",
    "answer": contains("string"),
    "hint": "strcmp compares two C-style strings; look for pointers or buffers passed in."
  },
  {
    "id": 133,
    "type": "text",
    "prompt": "Step 5: Assembly shows 'lea rax, [rbp-0x30]'. What short token describes what LEA does here (one token)?",
    "answer": contains("address"),
    "hint": "LEA computes the effective address without performing a memory load."
  },
  {
    "id": 134,
    "type": "mcq",
    "prompt": "Step 6: You find 'call 0x401200' in a function. Which immediate next action best helps you understand what that call does?",
    "choices": ["Go to target", "Rename here", "Delete call", "Export binary"],
    "answer": 0,
    "hint": "Navigate to the called function or decompile it to inspect behavior."
  },
  {
    "id": 135,
    "type": "text",
    "prompt": "Step 7: At a call site you observe registers set like 'mov rdi, rbx' then 'mov rsi, 0x20' before calling. Give two words describing what those registers likely are (two words).",
    "answer": contains("function args"),
    "hint": "On x86_64, rdi/rsi/rdx/... commonly hold the first arguments to a function."
  },
  {
    "id": 136,
    "type": "mcq",
    "prompt": "Step 8: The decompiler returns 'if (strcmp(a, b) == 0)'. What is the condition checking?",
    "choices": ["Strings equal", "Strings different", "Buffer overflow", "Null pointer"],
    "answer": 0,
    "hint": "strcmp returns 0 when two strings match exactly."
  },
  {
    "id": 137,
    "type": "text",
    "prompt": "Step 9: You see repeated writes like 'mov QWORD PTR [rbp-0x40], rax' filling a buffer. Provide one token naming the risk you should check for (one token).",
    "answer": contains("overflow"),
    "hint": "Repeated writes into a fixed buffer can overflow if bounds aren't checked."
  },
  {
    "id": 138,
    "type": "text",
    "prompt": "Step 10: A decompiled expression shows 'buf[i] = input[j]'. What short two-word step helps confirm safe behavior before trusting this code?",
    "answer": contains("check bounds"),
    "hint": "Verify indices are checked against buffer sizes to avoid out-of-bounds writes."
  },
  {
    "id": 139,
    "type": "mcq",
    "prompt": "Step 11: The function returns an integer stored in RAX on x86_64. Which short label is most informative to rename the return value if it indicates success/failure?",
    "choices": ["status", "tmp", "v1", "junk"],
    "answer": 0,
    "hint": "Rename return values to 'status' or 'ret' to document meaning; 'tmp' is not descriptive."
  },
  {
    "id": 140,
    "type": "text",
    "prompt": "Step 12: You encounter a magic constant 0x1F4 used when allocating memory. Give one short phrase (two words) describing how to discover what size it represents in decimal.",
    "answer": contains("convert decimal"),
    "hint": "Translate the hex to decimal or inspect how that value is used (bytes, objects)."
  },
  {
    "id": 141,
    "type": "mcq",
    "prompt": "Step 13: A function checks 'if (eax < 0)'. Which behavior does this typically indicate about eax?",
    "choices": ["error code", "positive length", "pointer value", "random data"],
    "answer": 0,
    "hint": "Negative return values often signal error codes from calls."
  },
  {
    "id": 142,
    "type": "text",
    "prompt": "Step 14: You see 'xor eax, eax' before returning. In one short token what common action does this perform (one token)?",
    "answer": contains("zero"),
    "hint": "XOR a register with itself zeroes it efficiently, commonly used to return 0."
  },
  {
    "id": 143,
    "type": "text",
    "prompt": "Step 15: The code dereferences a pointer loaded from a global and then calls a function pointer. Provide one short phrase (two words) describing what you should do to understand this indirect call.",
    "answer": contains("resolve pointer"),
    "hint": "Find where the global is set or examine initialization code to find the actual function."
  },
  {
    "id": 144,
    "type": "mcq",
    "prompt": "Step 16: You want to find all places that pass a buffer to 'memcpy'. Which Ghidra action is best for that?",
    "choices": ["Find References", "Create Bookmark", "Export Program", "Run Script"],
    "answer": 0,
    "hint": "Find References/Xrefs shows all call sites for the function."
  },
  {
    "id": 145,
    "type": "text",
    "prompt": "Step 17: After renaming locals and applying types, the decompiler reads clearer. What one short phrase (two words) describes your next documentation step to help others?",
    "answer": contains("add comments"),
    "hint": "Annotate tricky logic with comments explaining assumptions and evidence."
  },
  {
    "id": 146,
    "type": "mcq",
    "prompt": "Step 18: To test a hypothesis about input causing a crash, which safe step should you take before running the program with crafted input?",
    "choices": ["Use debugger", "Delete files", "Rename binary", "Disable analysis"],
    "answer": 0,
    "hint": "Run under a debugger or in an isolated VM to observe behavior safely."
  },
  {
    "id": 147,
    "type": "text",
    "prompt": "Step 19: You reconstruct a short string built byte-by-byte in a loop. Give one short two-word step to verify its final value at runtime.",
    "answer": contains("print string"),
    "hint": "Log or print the buffer in a debugger or instrumented run to confirm contents."
  },
  {
    "id": 148,
    "type": "text",
    "prompt": "Step 20: You finished analyzing the function. Provide one short phrase (three words) describing how to package your findings for handoff.",
    "answer": contains("write analysis report"),
    "hint": "Include renamed symbols, types, control-flow notes, and reproducible steps to test behaviors."
  }
  ]
