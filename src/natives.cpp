#include "tracer.hpp"

namespace tracer {

namespace {

std::string join(const std::vector<std::string>& lines) {
	std::string text;
	for (const std::string& line : lines) {
		if (!text.empty()) {
			text += '\n';
		}
		text += line;
	}
	return text;
}

bool setString(AMX* amx, cell address, cell size, const std::string& text) {
	Script* script = findScript(amx);
	if (script == nullptr || script->api == nullptr || size <= 0) {
		return false;
	}
	cell* physical;
	if (script->api->GetAddr(address, &physical) != AMX_ERR_NONE) {
		return false;
	}
	return script->api->SetString(physical, StringView(text.data(), text.size()), false, false, size_t(size)) == AMX_ERR_NONE;
}

void printLines(const char* title, const std::vector<std::string>& lines) {
	std::vector<std::string> block;
	block.push_back(std::string("[Tracer] ") + title);
	for (const std::string& line : lines) {
		block.push_back("[Tracer]   " + line);
	}
	printBlock(LogLevel::Message, block);
}

cell AMX_NATIVE_CALL PrintBacktrace(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	printLines("Backtrace:", currentBacktrace(false));
	return 1;
}

cell AMX_NATIVE_CALL GetBacktrace(AMX* amx, const cell* params) {
	return setString(amx, params[1], params[2], join(currentBacktrace(false)));
}

cell AMX_NATIVE_CALL PrintNativeBacktrace(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	printLines("Native backtrace:", nativeBacktrace(nullptr));
	return 1;
}

cell AMX_NATIVE_CALL GetNativeBacktrace(AMX* amx, const cell* params) {
	return setString(amx, params[1], params[2], join(nativeBacktrace(nullptr)));
}

cell AMX_NATIVE_CALL SetTracerLongCallTime(AMX* amx, const cell* params) {
	(void)amx;
	setLongCallTime(params[1]);
	return 1;
}

cell AMX_NATIVE_CALL GetTracerLongCallTime(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	return state().longCallCurrent;
}

cell AMX_NATIVE_CALL GetTracerDefaultLongCallTime(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	return state().settings.longCallTime;
}

cell AMX_NATIVE_CALL ResetTracerLongCallTime(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	setLongCallTime(state().settings.longCallTime);
	return 1;
}

cell AMX_NATIVE_CALL EnableTracerLongCall(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	state().longCallEnabled = true;
	return 1;
}

cell AMX_NATIVE_CALL DisableTracerLongCall(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	State& s = state();
	s.longCallEnabled = false;
	s.longCallLimitAt = UINT64_MAX;
	return 1;
}

cell AMX_NATIVE_CALL IsTracerLongCallEnabled(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	State& s = state();
	return s.longCallEnabled && s.longCallCurrent != 0;
}

cell AMX_NATIVE_CALL RestartTracerLongCall(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	restartLongCall();
	return 1;
}

#if defined TRACER_TEST_NATIVES
/**
 * Volatile at both levels, so no compiler drops the write to it.
 */
volatile int* volatile crashTarget = nullptr;

cell AMX_NATIVE_CALL TestTracerCrash(AMX* amx, const cell* params) {
	(void)amx;
	(void)params;
	*crashTarget = 1;
	return 0;
}
#endif

const AMX_NATIVE_INFO natives[] = {
	{ "PrintBacktrace", PrintBacktrace },
	{ "GetBacktrace", GetBacktrace },
	{ "PrintNativeBacktrace", PrintNativeBacktrace },
	{ "GetNativeBacktrace", GetNativeBacktrace },
	{ "PrintAmxBacktrace", PrintBacktrace },
	{ "GetAmxBacktrace", GetBacktrace },
	{ "SetTracerLongCallTime", SetTracerLongCallTime },
	{ "GetTracerLongCallTime", GetTracerLongCallTime },
	{ "GetTracerDefaultLongCallTime", GetTracerDefaultLongCallTime },
	{ "ResetTracerLongCallTime", ResetTracerLongCallTime },
	{ "EnableTracerLongCall", EnableTracerLongCall },
	{ "DisableTracerLongCall", DisableTracerLongCall },
	{ "IsTracerLongCallEnabled", IsTracerLongCallEnabled },
	{ "RestartTracerLongCall", RestartTracerLongCall },
	{ "Tracer_SetLongCallTime", SetTracerLongCallTime },
	{ "Tracer_GetLongCallTime", GetTracerLongCallTime },
	{ "Tracer_GetDefaultLongCallTime", GetTracerDefaultLongCallTime },
	{ "Tracer_ResetLongCallTime", ResetTracerLongCallTime },
	{ "Tracer_EnableLongCall", EnableTracerLongCall },
	{ "Tracer_DisableLongCall", DisableTracerLongCall },
	{ "Tracer_IsLongCallEnabled", IsTracerLongCallEnabled },
	{ "Tracer_RestartLongCall", RestartTracerLongCall },
#if defined TRACER_TEST_NATIVES
	{ "TestTracerCrash", TestTracerCrash },
#endif
};

}

void registerNatives(IPawnScript& script) {
	script.Register(natives, int(sizeof natives / sizeof natives[0]));
}

}
