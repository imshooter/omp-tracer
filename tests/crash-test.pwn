#include <open.mp>
#include <tracer>

/**
 * A crash on purpose, for a build with TRACER_TEST_NATIVES on: TestTracerCrash writes to address 0 from a native
 * called two functions deep in a timer. Tracer prints what crashed, the Pawn and native backtraces, the registers
 * and the modules of the server.
 */

native TestTracerCrash();

main() {}

stock Inner(value) {
    TestTracerCrash();

    return value;
}

stock Outer(value) {
    return Inner(value + 1);
}

forward @Test_Crash();
public @Test_Crash() {
    printf("[test] crash start");
    Outer(1);

    return 1;
}

public OnGameModeInit() {
    SetTimer("@Test_Crash", 300, false);

    return 1;
}
