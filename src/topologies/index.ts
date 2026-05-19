import { constrainedTopology } from "./constrained.js";
import { crossFederationTopology } from "./cross-federation.js";
import { hierarchicalTopology } from "./hierarchical.js";
import { multiAnchorTopology } from "./multi-anchor.js";
import { policyOperatorsTopology } from "./policy-operators.js";
import { singleAnchorTopology } from "./single-anchor.js";
import type { TopologyDefinition } from "./types.js";

export const topologies: readonly TopologyDefinition[] = [
	singleAnchorTopology,
	hierarchicalTopology,
	multiAnchorTopology,
	crossFederationTopology,
	constrainedTopology,
	policyOperatorsTopology,
];

export {
	constrainedTopology,
	crossFederationTopology,
	hierarchicalTopology,
	multiAnchorTopology,
	policyOperatorsTopology,
	singleAnchorTopology,
};

export type { EntityDefinition, TopologyDefinition } from "./types.js";
