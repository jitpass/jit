#ifndef SCREENLOCK_H
#define SCREENLOCK_H

// sl_observe_distributed subscribes to one named distributed notification
// (CFNotificationCenterGetDistributedCenter). Callable from any thread:
// delivery ALWAYS happens on the process's MAIN run loop (empirically
// verified — see the package doc comment), no matter where the observer
// was registered, which is why sl_run_main below exists.
void sl_observe_distributed(const char *name);

// sl_watch_power registers for system power notifications
// (IORegisterForSystemPower), attaching the source to the MAIN run loop
// explicitly, so it too is delivered wherever sl_run_main runs. Sleep is
// reported to Go as the pseudo-name sl_power_sleep_name (it is not a
// distributed notification). Best-effort: failure to register is silent —
// the caller keeps its idle-TTL fallback either way.
void sl_watch_power(void);

// sl_power_sleep_name is the pseudo notification name the power callback
// hands to Go for kIOMessageSystemWillSleep — namespaced so it can never
// collide with a real distributed notification some other process posts.
extern const char *sl_power_sleep_name;

// sl_is_main_thread reports (1/0) whether the calling thread is the
// process's main thread — the only thread sl_run_main may run on.
int sl_is_main_thread(void);

// sl_run_main parks the calling thread (which MUST be the main thread) in
// the main run loop, delivering the callbacks registered above, until
// sl_stop_main. Returns after sl_stop_main.
void sl_run_main(void);

// sl_stop_main stops sl_run_main from any thread. Safe to call before
// sl_run_main has entered the loop: the stop is queued as a run-loop block
// and executes the moment the loop starts, so the stop/run race can't
// strand the loop running forever.
void sl_stop_main(void);

// sl_post_distributed posts a distributed notification. TEST-ONLY: the
// package test uses it to drive the full register/deliver/callback path
// with a jit-namespaced name. Never call it with a name owned by the OS
// ("com.apple.screenIsLocked" would tell every password manager on the
// machine the screen just locked).
void sl_post_distributed(const char *name);

#endif
