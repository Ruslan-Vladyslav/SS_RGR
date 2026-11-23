
class MeshRouter {
  constructor() {
    this.adjacency = new Map();
  }

  addNode(nodeId) {
    if (!this.adjacency.has(nodeId)) {
      this.adjacency.set(nodeId, new Map());
    }
  }

  addLink(nodeA, nodeB, weight = 1) {
    this.addNode(nodeA);
    this.addNode(nodeB);
    this.adjacency.get(nodeA).set(nodeB, weight);
    this.adjacency.get(nodeB).set(nodeA, weight);
  }

  getNeighbors(nodeId) {
    if (!this.adjacency.has(nodeId)) return [];
    return Array.from(this.adjacency.get(nodeId).keys());
  }

  getAllNodes() {
    return Array.from(this.adjacency.keys());
  }

  findRoute(source, destination) {
    if (source === destination) {
      return { path: [source], distance: 0 };
    }
    if (!this.adjacency.has(source) || !this.adjacency.has(destination)) {
      return null;
    }

    const distances = new Map();
    const previous = new Map();
    const unvisited = new Set(this.adjacency.keys());

    for (const node of unvisited) {
      distances.set(node, Infinity);
    }
    distances.set(source, 0);

    while (unvisited.size > 0) {
      let closestNode = null;
      let minDistance = Infinity;
      for (const node of unvisited) {
        const d = distances.get(node);
        if (d < minDistance) {
          minDistance = d;
          closestNode = node;
        }
      }

      if (closestNode === null || minDistance === Infinity) {
        break;
      }

      if (closestNode === destination) {
        break;
      }

      unvisited.delete(closestNode);

      const neighbors = this.adjacency.get(closestNode);
      for (const [neighbor, weight] of neighbors.entries()) {
        if (!unvisited.has(neighbor)) continue;

        const alt = distances.get(closestNode) + weight;
        if (alt < distances.get(neighbor)) {
          distances.set(neighbor, alt);
          previous.set(neighbor, closestNode);
        }
      }
    }

    if (!previous.has(destination)) {
      return null;
    }

    const path = [];
    let curr = destination;
    while (curr) {
      path.unshift(curr);
      curr = previous.get(curr);
    }

    return {
      path,
      distance: distances.get(destination),
    };
  }

  renderTopology() {
    const lines = [];
    lines.push('NETWORK TOPOLOGY');
    for (const [node, neighbors] of this.adjacency.entries()) {
      const neighborList = Array.from(neighbors.keys()).join(', ');
      lines.push(`  [ ${node} ] <---> { ${neighborList} }`);
    }
    return lines.join('\n');
  }
}

function createDefaultLabMeshTopology() {
  const router = new MeshRouter();
  router.addLink('Node_A', 'Node_B');
  router.addLink('Node_A', 'Node_C');
  router.addLink('Node_B', 'Node_D');
  router.addLink('Node_C', 'Node_D');
  router.addLink('Node_C', 'Node_E');
  router.addLink('Node_C', 'Node_F');
  router.addLink('Node_D', 'Node_F');
  router.addLink('Node_E', 'Node_F');
  return router;
}
module.exports = {
  MeshRouter,
  createDefaultLabMeshTopology,
};

