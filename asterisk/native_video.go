package asterisk

import (
	"fmt"

	"github.com/google/uuid"
)

func (r *Router) OriginateVideoToExtension(extension, bridgeID, callerID, callID, fromNode string, timeoutSec int) (string, error) {
	channel := fmt.Sprintf("PJSIP/%s", extension)
	actionID := uuid.NewString()
	r.TrackPendingPrefix(callID, fmt.Sprintf("PJSIP/%s-", extension))
	r.originateMu.Lock()
	r.actionIDToCallID[actionID] = callID
	r.originateMu.Unlock()
	variables := map[string]string{
		"SIMSON_CALL_ID": callID, "__SIMSON_CALL_ID": callID,
		"SIMSON_FROM_NODE": fromNode, "__SIMSON_FROM_NODE": fromNode,
		"SIMSON_BRIDGE_ID": bridgeID, "__SIMSON_BRIDGE_ID": bridgeID,
	}
	_, err := r.ami.OriginateWithVarsAndCodecs(channel, "from-simson-video-source", bridgeID, callerID, timeoutSec*1000, actionID, variables, "ulaw,alaw,h264")
	if err != nil {
		r.originateMu.Lock()
		delete(r.actionIDToCallID, actionID)
		r.originateMu.Unlock()
		return "", err
	}
	return actionID, nil
}
