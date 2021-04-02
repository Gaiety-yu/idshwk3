global AgentTable :table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value: string) {
	local orig_addr: addr = c$id$orig_h; 
	if (name == "USER-AGENT"){
	  local agent: string = to_lower(value);
		if (orig_addr in AgentTable) {
			add AgentTable[orig_addr][agent];
		} 
    else {
			AgentTable[orig_addr] = set(agent);
		}
	}
}

event zeek_done() {
	for (orig_addr in AgentTable) {
		if (|AgentTable[orig_addr]| >= 3) {
			print fmt("%s is a proxy",orig_addr);
		}
	}
}
