/*
 * Arduino build bridge.
 *
 * The implementation remains canonical in c/src/mqttsn.c. This translation
 * unit includes it so Arduino builds exercise the exact same source rather
 * than maintaining a fork.
 */
#include "../../c/src/mqttsn.c"
