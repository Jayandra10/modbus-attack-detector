# Zeek configuration for Phase 1 Modbus monitoring
# Minimal config - JSON output handled via command-line arguments

@load base/protocols/conn

event zeek_init() {
    print "Zeek monitoring started";
}

event zeek_done() {
    print "Zeek monitoring ended";
}
