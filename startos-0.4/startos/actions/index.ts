import { sdk } from '../sdk'

// No StartOS-side actions: every knob (node name, accept mode, storage cap)
// is operated live from the Blindspark dashboard itself.
export const actions = sdk.Actions.of()
