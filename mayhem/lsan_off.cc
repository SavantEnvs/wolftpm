/* Leak detection is off for every target in this layer: leaks are not the bug
 * class this fleet fuzzes for, and -fsanitize=address always bundles LSan in
 * with no flag to drop just it. ASan and UBSan stay fully active. */
extern "C" int __lsan_is_turned_off() { return 1; }
