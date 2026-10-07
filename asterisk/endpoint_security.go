package asterisk

import (
	"fmt"
	"sort"
	"strings"
)

func endpointAccountSources(endpoints []SIPEndpointDef) map[string]string {
	members := map[string]map[string]bool{}
	for _, endpoint := range endpoints {
		if !endpoint.Enabled {
			continue
		}
		identity := sanitizeID(endpoint.Extension)
		if identity == "" {
			identity = sanitizeID(endpoint.ID)
		}
		if identity == "" {
			continue
		}
		if members[endpoint.AccountID] == nil {
			members[endpoint.AccountID] = map[string]bool{}
		}
		members[endpoint.AccountID][identity] = true
	}
	result := map[string]string{}
	for account, identities := range members {
		names := make([]string, 0, len(identities))
		for identity := range identities {
			names = append(names, identity)
		}
		sort.Strings(names)
		clauses := make([]string, 0, len(names))
		for _, identity := range names {
			clauses = append(clauses, fmt.Sprintf("\"${CHANNEL(pjsip,endpoint)}\" = \"%s\"", identity))
		}
		result[account] = strings.Join(clauses, " | ")
	}
	return result
}

func appendEndpointAccountGuard(builder *strings.Builder, allowed string) {
	if allowed == "" {
		allowed = "0"
	}
	builder.WriteString(" same  => n,GotoIf($[\"${CHANNEL(channeltype)}\" = \"Local\"]?simson-source-ok)\n")
	fmt.Fprintf(builder, " same  => n,GotoIf($[%s]?simson-source-ok)\n", allowed)
	builder.WriteString(" same  => n,Log(WARNING,Simson denied SIP endpoint ${CHANNEL(pjsip,endpoint)} calling ${EXTEN} outside its account)\n")
	builder.WriteString(" same  => n,Hangup(21)\n")
	builder.WriteString(" same  => n(simson-source-ok),NoOp(Simson source authorized)\n")
}
