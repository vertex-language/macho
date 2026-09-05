package link_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vertex-language/macho"
	"github.com/vertex-language/macho/link"

	_ "github.com/vertex-language/macho/arm64"
)

// linkAndRun compiles one C source with clang, links it with this
// linker, runs it, and returns the exit status.
//
// It goes through clang because what these tests are about is reading
// an object another toolchain wrote — the descriptors, the relocations
// and the section types are all its output, and a hand-built object
// would be this package agreeing with itself.
func linkAndRun(t *testing.T, src string) int {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not found on PATH")
	}
	tbdPath := realLibSystemTBD()
	if tbdPath == "" {
		t.Skip("no known libSystem.tbd found on this machine")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("running the linked binary needs arm64 macOS")
	}

	dir := t.TempDir()
	cPath := filepath.Join(dir, "t.c")
	objPath := filepath.Join(dir, "t.o")
	if err := os.WriteFile(cPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(clang, "-c", "-target", "arm64-apple-macos14.0",
		"-O0", "-o", objPath, cPath).CombinedOutput()
	if err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}

	target, err := macho.ParseTarget("arm64-apple-macos14.0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := link.New(target)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	objData, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.AddObject("t.o", objData); err != nil {
		t.Fatalf("AddObject: %v", err)
	}
	tbdData, err := os.ReadFile(tbdPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.AddStub("libSystem", tbdData); err != nil {
		t.Fatal(err)
	}
	l.Options().Output = link.OutputExecute
	l.SetEntry("_main")

	img, err := l.Link()
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	bytes, err := img.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	exePath := filepath.Join(dir, "a.out")
	if err := os.WriteFile(exePath, bytes, 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exePath)
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("running the linked binary: %v", err)
		}
	}
	return cmd.ProcessState.ExitCode()
}

// TestPointerToAnImportBinds: a pointer in data initialized to a symbol
// from a dylib.
//
// It has no address at link time — dyld writes it — so the field holds
// the bind's addend and the fixup carries the rest. Resolving it instead
// asks an unbound symbol for its address, which is where this used to
// stop: "_puts is unbound", on a pattern as ordinary as a table of
// function pointers.
func TestPointerToAnImportBinds(t *testing.T) {
	if got := linkAndRun(t, `
#include <unistd.h>
static ssize_t (*writer)(int, const void *, size_t) = write;
int main(void) { return writer(1, "", 0) == 0 ? 42 : 1; }
`); got != 42 {
		t.Errorf("exit status = %d, want 42", got)
	}
}

// TestThreadLocalsRun is thread-local storage end to end.
//
// Four things have to be right at once and each was wrong on its own:
// the descriptor's offset field is a distance from the template region
// rather than an address, __thread_vars is pointer-aligned however its
// input declared it, the header says MH_HAS_TLV_DESCRIPTORS so dyld sets
// a block up at all, and the ADRP/LDR pair is relaxed to ADRP/ADD for a
// descriptor defined here. Any one of them missing is a crash on the
// first read of a thread-local rather than a link error.
func TestThreadLocalsRun(t *testing.T) {
	if got := linkAndRun(t, `
_Thread_local int counter = 7;
_Thread_local long wide = 100;
_Thread_local int zeroed;

int main(void) {
    if (counter != 7 || wide != 100 || zeroed != 0) return 1;
    counter += 35;
    return counter;
}
`); got != 42 {
		t.Errorf("exit status = %d, want 42", got)
	}
}

// TestThreadLocalsArePerThread: the storage is a template, and every
// thread gets its own copy of it.
//
// A descriptor whose offset field held an address rather than an offset
// still runs — it reads and writes some memory — and it is one shared
// location for every thread. That is the failure this catches and the
// single-threaded test above cannot.
func TestThreadLocalsArePerThread(t *testing.T) {
	if got := linkAndRun(t, `
#include <pthread.h>
_Thread_local int counter = 7;
_Thread_local long wide = 100;
_Thread_local int zeroed;

static void *worker(void *arg) {
    (void)arg;
    /* Each thread starts from the template, not from what main left. */
    if (counter != 7 || wide != 100 || zeroed != 0) return (void *)1;
    counter += 10; wide += 1; zeroed = 5;
    if (counter != 17 || wide != 101 || zeroed != 5) return (void *)2;
    return (void *)0;
}

int main(void) {
    counter = 1000; wide = 2000; zeroed = 3000;
    pthread_t t1, t2;
    void *r1, *r2;
    pthread_create(&t1, 0, worker, 0);
    pthread_join(t1, &r1);
    pthread_create(&t2, 0, worker, 0);
    pthread_join(t2, &r2);
    if (r1 || r2) return 1;
    /* main's own copy is untouched by either thread. */
    if (counter != 1000 || wide != 2000 || zeroed != 3000) return 2;
    return 42;
}
`); got != 42 {
		t.Errorf("exit status = %d, want 42", got)
	}
}
