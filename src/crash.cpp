#include "tracer.hpp"

#include <algorithm>
#include <cctype>
#include <mutex>

#if defined _WIN32
	#include <windows.h>
	#include <dbghelp.h>
	#include <psapi.h>
#else
	#include <climits>
	#include <cstdlib>
	#include <cstring>
	#include <thread>

	#include <cxxabi.h>
	#include <dlfcn.h>
	#include <link.h>
	#include <pthread.h>
	#include <semaphore.h>
	#include <signal.h>
	#include <time.h>
	#include <ucontext.h>
	#include <unistd.h>
	#include <unwind.h>
#endif

namespace tracer {

namespace {

constexpr int MaximumNativeFrames = 32;

bool installed = false;
bool crashing = false;

std::string hex(uint32_t value) {
	char buffer[16];
	std::snprintf(buffer, sizeof(buffer), "%08X", value);
	return buffer;
}

std::string generatedCode(uintptr_t address) {
	State& s = state();
	AMX* amx = s.watch.amx.load(std::memory_order_relaxed);
	cell cip, frm;
	if (s.jit == nullptr || amx == nullptr || !s.jit->locate(amx, address, 0, cip, frm)) {
		return std::string();
	}
	Script* script = findScript(amx);
	if (script == nullptr) {
		return std::string();
	}
	std::string where = location(*script, cip);
	return "code PawnJIT generated for " + script->name + (where.empty() ? std::string() : ", at " + where);
}

#if defined _WIN32

LPTOP_LEVEL_EXCEPTION_FILTER previousFilter = nullptr;
std::mutex symbolLock;
bool symbolsReady = false;

void prepareSymbols() {
	if (symbolsReady) {
		return;
	}
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS);
	SymInitialize(GetCurrentProcess(), nullptr, TRUE);
	symbolsReady = true;
}

std::string symbolName(DWORD64 address) {
	alignas(SYMBOL_INFO) char buffer[sizeof(SYMBOL_INFO) + 256];
	auto* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
	symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	symbol->MaxNameLen = 255;
	DWORD64 displacement = 0;
	if (!SymFromAddr(GetCurrentProcess(), address, &displacement, symbol)) {
		return std::string();
	}
	IMAGEHLP_MODULE64 module = {};
	module.SizeOfStruct = sizeof(module);
	bool real = SymGetModuleInfo64(GetCurrentProcess(), address, &module) && (module.SymType == SymPdb || module.SymType == SymDia || module.SymType == SymCoff || module.SymType == SymCv);
	if (!real && displacement > 0x40) {
		return std::string();
	}
	char offset[32];
	std::snprintf(offset, sizeof(offset), "+0x%X", unsigned(displacement));
	return std::string(symbol->Name) + offset;
}

std::string describeAddress(uintptr_t address) {
	std::string text;
	HMODULE module = nullptr;
	char path[MAX_PATH] = "";
	if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCSTR>(address), &module) && module != nullptr) {
		GetModuleFileNameA(module, path, MAX_PATH);
		std::string name = path;
		size_t slash = name.find_last_of("/\\");
		if (slash != std::string::npos) {
			name = name.substr(slash + 1);
		}
		char offset[32];
		std::snprintf(offset, sizeof(offset), "+0x%X", unsigned(address - uintptr_t(module)));
		text = name + offset;
		std::string symbol = symbolName(DWORD64(address));
		if (!symbol.empty()) {
			text += " (" + symbol + ")";
		}
		return text;
	}
	text = "0x" + hex(uint32_t(address));
	std::string generated = generatedCode(address);
	if (!generated.empty()) {
		text += " (" + generated + ")";
	}
	return text;
}

std::vector<std::string> walk(CONTEXT context) {
	std::vector<std::string> lines;
	std::lock_guard<std::mutex> guard(symbolLock);
	prepareSymbols();
	STACKFRAME64 frame = {};
	frame.AddrPC.Offset = context.Eip;
	frame.AddrPC.Mode = AddrModeFlat;
	frame.AddrFrame.Offset = context.Ebp;
	frame.AddrFrame.Mode = AddrModeFlat;
	frame.AddrStack.Offset = context.Esp;
	frame.AddrStack.Mode = AddrModeFlat;
	HANDLE process = GetCurrentProcess();
	HANDLE thread = GetCurrentThread();
	for (int number = 0; number != MaximumNativeFrames; ++number) {
		if (!StackWalk64(IMAGE_FILE_MACHINE_I386, process, thread, &frame, &context, nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr) || frame.AddrPC.Offset == 0) {
			break;
		}
		lines.push_back("#" + std::to_string(number) + " " + describeAddress(uintptr_t(frame.AddrPC.Offset)));
	}
	return lines;
}

std::string exceptionText(const EXCEPTION_RECORD& record) {
	switch (record.ExceptionCode) {
	case EXCEPTION_ACCESS_VIOLATION:
		if (record.NumberParameters >= 2) {
			const char* kind = record.ExceptionInformation[0] == 1 ? "writing" : (record.ExceptionInformation[0] == 8 ? "executing" : "reading");
			return std::string("access violation ") + kind + " address 0x" + hex(uint32_t(record.ExceptionInformation[1]));
		}
		return "access violation";
	case EXCEPTION_STACK_OVERFLOW:
		return "stack overflow";
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		return "illegal instruction";
	case EXCEPTION_PRIV_INSTRUCTION:
		return "privileged instruction";
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		return "integer division by zero";
	case EXCEPTION_INT_OVERFLOW:
		return "integer overflow";
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		return "floating point division by zero";
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		return "array bounds exceeded";
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		return "misaligned data";
	case EXCEPTION_IN_PAGE_ERROR:
		return "page error";
	default:
		return "exception 0x" + hex(uint32_t(record.ExceptionCode));
	}
}

std::vector<std::string> serverModules() {
	std::vector<std::string> lines;
	HMODULE modules[1024];
	DWORD needed = 0;
	if (!K32EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
		return lines;
	}
	char directory[MAX_PATH];
	DWORD length = GetCurrentDirectoryA(MAX_PATH, directory);
	std::string root(directory, length);
	std::transform(root.begin(), root.end(), root.begin(), [](unsigned char character) { return char(std::tolower(character)); });
	for (DWORD index = 0; index != std::min<DWORD>(needed / sizeof(HMODULE), 1024); ++index) {
		char path[MAX_PATH];
		DWORD size = GetModuleFileNameA(modules[index], path, MAX_PATH);
		std::string name(path, size);
		std::string lower = name;
		std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char character) { return char(std::tolower(character)); });
		if (lower.compare(0, root.size(), root) != 0) {
			continue;
		}
		MODULEINFO info = {};
		K32GetModuleInformation(GetCurrentProcess(), modules[index], &info, sizeof(info));
		uint32_t base = uint32_t(uintptr_t(info.lpBaseOfDll));
		lines.push_back(hex(base) + " - " + hex(base + info.SizeOfImage) + " " + shortPath(name.substr(root.size() + 1)));
	}
	return lines;
}

#else

constexpr int CrashSignals[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT };
constexpr int CrashSignalCount = int(sizeof CrashSignals / sizeof CrashSignals[0]);
constexpr size_t AlternateStackSize = 128 * 1024;
constexpr int InterruptWait = 2000;

struct sigaction previousActions[CrashSignalCount];
struct sigaction previousInterrupt;
std::vector<char> alternateStack;
stack_t previousStack;
bool stackReplaced = false;
std::thread interruptThread;
sem_t interruptWake;
bool interruptReady = false;
std::atomic<bool> interruptStop(false);
std::atomic<int> interruptStep(0);

std::string fileName(const char* path) {
	const char* slash = std::strrchr(path, '/');
	return slash != nullptr ? slash + 1 : path;
}

std::string describeAddress(uintptr_t address) {
	std::string text;
	Dl_info info;
	void* entry = nullptr;
	if (dladdr1(reinterpret_cast<void*>(address), &info, &entry, RTLD_DL_SYMENT) && info.dli_fname != nullptr && info.dli_fname[0] != '\0') {
		char offset[32];
		std::snprintf(offset, sizeof(offset), "+0x%X", unsigned(address - uintptr_t(info.dli_fbase)));
		text = fileName(info.dli_fname) + offset;
		const auto* symbol = static_cast<const ElfW(Sym)*>(entry);
		uintptr_t displacement = address - uintptr_t(info.dli_saddr);
		if (info.dli_sname != nullptr && symbol != nullptr && displacement < symbol->st_size) {
			int status = 0;
			char* demangled = abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);
			std::snprintf(offset, sizeof(offset), "+0x%X", unsigned(displacement));
			text += " (" + std::string(status == 0 && demangled != nullptr ? demangled : info.dli_sname) + offset + ")";
			std::free(demangled);
		}
		return text;
	}
	text = "0x" + hex(uint32_t(address));
	std::string generated = generatedCode(address);
	if (!generated.empty()) {
		text += " (" + generated + ")";
	}
	return text;
}

_Unwind_Reason_Code collectFrame(_Unwind_Context* context, void* data) {
	auto& frames = *static_cast<std::vector<uintptr_t>*>(data);
	int before = 0;
	uintptr_t address = uintptr_t(_Unwind_GetIPInfo(context, &before));
	if (address == 0) {
		return _URC_END_OF_STACK;
	}
	frames.push_back(address);
	return frames.size() == MaximumNativeFrames * 2 ? _URC_END_OF_STACK : _URC_NO_REASON;
}

__attribute__((noinline)) std::vector<uintptr_t> unwind() {
	std::vector<uintptr_t> frames;
	frames.reserve(MaximumNativeFrames * 2);
	_Unwind_Backtrace(collectFrame, &frames);
	return frames;
}

std::vector<std::string> describeFrames(const std::vector<uintptr_t>& frames, size_t from) {
	std::vector<std::string> lines;
	for (size_t index = from; index < frames.size() && lines.size() != MaximumNativeFrames; ++index) {
		lines.push_back("#" + std::to_string(lines.size()) + " " + describeAddress(frames[index]));
	}
	return lines;
}

std::vector<std::string> walk(uintptr_t eip) {
	std::vector<uintptr_t> frames = unwind();
	auto found = std::find(frames.begin(), frames.end(), eip);
	if (found == frames.end()) {
		return { "#0 " + describeAddress(eip) };
	}
	return describeFrames(frames, size_t(found - frames.begin()));
}

std::string signalText(int number, const siginfo_t& information, const greg_t* registers) {
	uintptr_t address = uintptr_t(information.si_addr);
	switch (number) {
	case SIGSEGV: {
		uintptr_t esp = uintptr_t(registers[REG_ESP]);
		if (address + 65536 >= esp && address < esp + 4096) {
			return "stack overflow";
		}
		if (registers[REG_TRAPNO] != 14) {
			return "segmentation fault";
		}
		const char* kind = (registers[REG_ERR] & 0x10) || address == uintptr_t(registers[REG_EIP]) ? "executing" : ((registers[REG_ERR] & 0x2) ? "writing" : "reading");
		return std::string("segmentation fault ") + kind + " address 0x" + hex(uint32_t(address));
	}
	case SIGBUS:
		return information.si_code == BUS_ADRALN ? "misaligned data" : "bus error at address 0x" + hex(uint32_t(address));
	case SIGILL:
		return information.si_code == ILL_PRVOPC || information.si_code == ILL_PRVREG ? "privileged instruction" : "illegal instruction";
	case SIGFPE:
		switch (information.si_code) {
		case FPE_INTDIV:
			return "integer division by zero";
		case FPE_INTOVF:
			return "integer overflow";
		case FPE_FLTDIV:
			return "floating point division by zero";
		default:
			return "floating point error";
		}
	case SIGABRT:
		return "abort";
	default:
		return "signal " + std::to_string(number);
	}
}

struct ModuleSearch {
	std::string root;
	std::vector<std::string> lines;
};

int listModule(dl_phdr_info* info, size_t size, void* data) {
	(void)size;
	auto& search = *static_cast<ModuleSearch*>(data);
	std::string path = info->dlpi_name != nullptr ? info->dlpi_name : "";
	if (path.empty()) {
		char executable[PATH_MAX];
		ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
		if (length <= 0) {
			return 0;
		}
		path.assign(executable, size_t(length));
	} else if (path.find('/') == std::string::npos) {
		return 0;
	} else if (path[0] != '/') {
		path = search.root + "/" + path;
	}
	if (path.compare(0, search.root.size() + 1, search.root + "/") != 0) {
		return 0;
	}
	uintptr_t low = UINTPTR_MAX;
	uintptr_t high = 0;
	for (int index = 0; index != info->dlpi_phnum; ++index) {
		const ElfW(Phdr)& header = info->dlpi_phdr[index];
		if (header.p_type == PT_LOAD) {
			low = std::min<uintptr_t>(low, info->dlpi_addr + header.p_vaddr);
			high = std::max<uintptr_t>(high, info->dlpi_addr + header.p_vaddr + header.p_memsz);
		}
	}
	if (high != 0) {
		search.lines.push_back(hex(uint32_t(low)) + " - " + hex(uint32_t(high)) + " " + shortPath(path.substr(search.root.size() + 1)));
	}
	return 0;
}

std::vector<std::string> serverModules() {
	ModuleSearch search;
	char directory[PATH_MAX];
	if (getcwd(directory, sizeof(directory)) == nullptr) {
		return {};
	}
	search.root = directory;
	dl_iterate_phdr(listModule, &search);
	return search.lines;
}

/**
 * Hand a signal to the handler that was there before. When that is the default action, a crash signal returns to
 * the instruction that raised it, so it raises it again under that action, and a signal sent by a process is raised
 * once more.
 */
void forwardSignal(int number, siginfo_t* information, void* context, const struct sigaction& previous) {
	if (previous.sa_flags & SA_SIGINFO) {
		previous.sa_sigaction(number, information, context);
	} else if (previous.sa_handler != SIG_DFL && previous.sa_handler != SIG_IGN) {
		previous.sa_handler(number);
	} else {
		sigaction(number, &previous, nullptr);
		if (information == nullptr || information->si_code <= 0) {
			raise(number);
		}
	}
}

#endif

void reportCrash(const std::string& what, uintptr_t address, bool mainThread, const std::vector<std::string>& frames, const std::vector<std::string>& registers) {
	State& s = state();
	std::vector<std::string> lines;
	lines.push_back("[Tracer] The server crashed: " + what);
	lines.push_back("[Tracer]   in " + describeAddress(address));
	if (mainThread && !s.calls.empty()) {
		const Call& top = s.calls.back();
		if (top.kind == CallKind::Native) {
			std::string where = location(*top.script, top.cip - cell(sizeof(cell)));
			lines.push_back("[Tracer]   while " + top.script->name + " ran native " + top.script->nativeName(top.index) + (where.empty() ? std::string() : ", called at " + where));
		} else {
			lines.push_back("[Tracer]   while " + top.script->name + " ran Pawn code");
		}
		lines.push_back("[Tracer]   Pawn backtrace:");
		for (const std::string& frame : currentBacktrace(true)) {
			lines.push_back("[Tracer]     " + frame);
		}
	} else if (!mainThread) {
		lines.push_back("[Tracer]   on a thread other than the server thread");
	}
	lines.push_back("[Tracer]   native backtrace:");
	for (const std::string& frame : frames) {
		lines.push_back("[Tracer]     " + frame);
	}
	lines.push_back("[Tracer]   registers:");
	for (const std::string& line : registers) {
		lines.push_back("[Tracer]     " + line);
	}
	std::vector<std::string> modules = serverModules();
	if (!modules.empty()) {
		lines.push_back("[Tracer]   modules of the server:");
		for (const std::string& module : modules) {
			lines.push_back("[Tracer]     " + module);
		}
	}
	printBlock(LogLevel::Error, lines);
}

#if defined _WIN32

LONG WINAPI crashFilter(EXCEPTION_POINTERS* pointers) {
	State& s = state();
	if (!crashing && s.settings.crash && pointers != nullptr) {
		crashing = true;
		const EXCEPTION_RECORD& record = *pointers->ExceptionRecord;
		const CONTEXT& context = *pointers->ContextRecord;
		reportCrash(exceptionText(record), uintptr_t(record.ExceptionAddress), GetCurrentThreadId() == s.mainThread, walk(context), {
			"EAX " + hex(context.Eax) + "  EBX " + hex(context.Ebx) + "  ECX " + hex(context.Ecx) + "  EDX " + hex(context.Edx),
			"ESI " + hex(context.Esi) + "  EDI " + hex(context.Edi) + "  EBP " + hex(context.Ebp) + "  ESP " + hex(context.Esp),
			"EIP " + hex(context.Eip) + "  EFLAGS " + hex(context.EFlags)
		});
	}
	return previousFilter != nullptr ? previousFilter(pointers) : EXCEPTION_CONTINUE_SEARCH;
}

BOOL WINAPI consoleHandler(DWORD type) {
	State& s = state();
	if ((type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) && s.settings.enable && s.watch.callStart.load() != 0) {
		reportRunningCall(true);
	}
	return FALSE;
}

#else

void crashHandler(int number, siginfo_t* information, void* context) {
	State& s = state();
	auto* user = static_cast<ucontext_t*>(context);
	if (!crashing && s.settings.crash && information != nullptr && user != nullptr) {
		crashing = true;
		const greg_t* registers = user->uc_mcontext.gregs;
		uintptr_t eip = uintptr_t(registers[REG_EIP]);
		reportCrash(signalText(number, *information, registers), eip, (unsigned long)pthread_self() == s.mainThread, walk(eip), {
			"EAX " + hex(registers[REG_EAX]) + "  EBX " + hex(registers[REG_EBX]) + "  ECX " + hex(registers[REG_ECX]) + "  EDX " + hex(registers[REG_EDX]),
			"ESI " + hex(registers[REG_ESI]) + "  EDI " + hex(registers[REG_EDI]) + "  EBP " + hex(registers[REG_EBP]) + "  ESP " + hex(registers[REG_ESP]),
			"EIP " + hex(registers[REG_EIP]) + "  EFLAGS " + hex(registers[REG_EFL])
		});
	}
	for (int index = 0; index != CrashSignalCount; ++index) {
		if (CrashSignals[index] == number) {
			sigaction(number, &previousActions[index], nullptr);
			forwardSignal(number, information, context, previousActions[index]);
		}
	}
}

/**
 * The console interrupts the server on its own thread: the report is written by another thread while this one
 * waits, so the server thread stands still, as Windows runs a console handler beside it.
 */
void interruptHandler(int number, siginfo_t* information, void* context) {
	State& s = state();
	int idle = 0;
	if (s.settings.enable && s.watch.callStart.load() != 0 && interruptStep.compare_exchange_strong(idle, 1)) {
		sem_post(&interruptWake);
		timespec pause = { 0, 1000000 };
		for (int waited = 0; waited != InterruptWait && interruptStep.load() != 2; ++waited) {
			nanosleep(&pause, nullptr);
		}
		interruptStep.store(0);
	}
	forwardSignal(number, information, context, previousInterrupt);
}

void interruptLoop() {
	while (!interruptStop.load()) {
		if (sem_wait(&interruptWake) != 0 || interruptStop.load()) {
			continue;
		}
		if (interruptStep.load() == 1) {
			reportRunningCall(true);
			interruptStep.store(2);
		}
	}
}

#endif

}

std::vector<std::string> nativeBacktrace(const void* context) {
#if defined _WIN32
	CONTEXT copy;
	if (context != nullptr) {
		copy = *static_cast<const CONTEXT*>(context);
	} else {
		RtlCaptureContext(&copy);
	}
	return walk(copy);
#else
	(void)context;
	return describeFrames(unwind(), 2);
#endif
}

void installCrashHandlers() {
	if (installed) {
		return;
	}
	installed = true;
#if defined _WIN32
	previousFilter = SetUnhandledExceptionFilter(crashFilter);
	SetConsoleCtrlHandler(consoleHandler, TRUE);
#else
	if ((unsigned long)pthread_self() == state().mainThread) {
		alternateStack.resize(AlternateStackSize);
		stack_t stack = {};
		stack.ss_sp = alternateStack.data();
		stack.ss_size = alternateStack.size();
		stackReplaced = sigaltstack(&stack, &previousStack) == 0;
	}
	struct sigaction action = {};
	action.sa_sigaction = crashHandler;
	action.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&action.sa_mask);
	for (int index = 0; index != CrashSignalCount; ++index) {
		sigaction(CrashSignals[index], &action, &previousActions[index]);
	}
	if (!interruptReady) {
		interruptReady = sem_init(&interruptWake, 0, 0) == 0;
	}
	sigset_t blocked, previousMask;
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGINT);
	pthread_sigmask(SIG_BLOCK, &blocked, &previousMask);
	interruptStop.store(false);
	interruptThread = std::thread(interruptLoop);
	pthread_sigmask(SIG_SETMASK, &previousMask, nullptr);
	action.sa_sigaction = interruptHandler;
	action.sa_flags = SA_SIGINFO;
	sigaction(SIGINT, &action, &previousInterrupt);
#endif
}

void removeCrashHandlers() {
	if (!installed) {
		return;
	}
	installed = false;
#if defined _WIN32
	SetUnhandledExceptionFilter(previousFilter);
	SetConsoleCtrlHandler(consoleHandler, FALSE);
#else
	for (int index = 0; index != CrashSignalCount; ++index) {
		sigaction(CrashSignals[index], &previousActions[index], nullptr);
	}
	sigaction(SIGINT, &previousInterrupt, nullptr);
	interruptStop.store(true);
	sem_post(&interruptWake);
	if (interruptThread.joinable()) {
		interruptThread.join();
	}
	if (stackReplaced) {
		sigaltstack(&previousStack, nullptr);
		stackReplaced = false;
	}
#endif
}

}
