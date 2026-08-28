import React, { useMemo, useState } from "react";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";

const SEV_RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, "": 0 };

function effectiveSeverity(node) {
  const a = (node.severity || "").toUpperCase();
  const b = (node.descendant_severity || "").toUpperCase();
  return SEV_RANK[a] >= SEV_RANK[b] ? a : b;
}

function sevClass(sev) {
  const s = (sev || "").toUpperCase();
  if (s === "CRITICAL") return "wmap-node--critical";
  if (s === "HIGH") return "wmap-node--high";
  if (s === "MEDIUM") return "wmap-node--medium";
  if (s === "LOW") return "wmap-node--low";
  return "";
}

function TreeNode({
  node,
  childrenByParent,
  nodesById,
  expanded,
  toggle,
  onSelect,
  selectedId,
  threatOnly,
  filterType,
  query,
}) {
  const kids = (childrenByParent[String(node.id)] || [])
    .map((id) => nodesById[String(id)])
    .filter(Boolean);
  const sev = effectiveSeverity(node);
  const isOpen = expanded.has(node.id);
  const hasKids = kids.length > 0;
  const direct = (node.finding_count || 0) > 0;
  const desc = (node.descendant_finding_count || 0) > 0;

  if (threatOnly && !direct && !desc && SEV_RANK[sev] < 4) {
    return null;
  }
  if (filterType && filterType !== "all") {
    const typeMap = {
      domains: ["domain", "subdomain"],
      urls: ["path", "endpoint"],
      apis: ["api"],
      ports: ["port", "service"],
      findings: [],
    };
    const allowed = typeMap[filterType];
    if (allowed && !allowed.includes(node.node_type) && !hasKids) return null;
  }
  if (query) {
    const q = query.toLowerCase();
    const selfMatch =
      (node.label || "").toLowerCase().includes(q) ||
      (node.url || "").toLowerCase().includes(q);
    // still render if descendants may match — keep simple: show if self matches or has kids
    if (!selfMatch && !hasKids) return null;
  }

  return (
    <li className={`wmap-li ${sevClass(sev)}`}>
      <div
        className={`wmap-row${selectedId === node.id ? " is-selected" : ""}${
          direct && SEV_RANK[sev] >= 4 ? " is-alert-link" : ""
        }`}
      >
        {hasKids ? (
          <button
            type="button"
            className="wmap-toggle"
            aria-label={isOpen ? "Collapse" : "Expand"}
            onClick={() => toggle(node.id)}
          >
            {isOpen ? "▾" : "▸"}
          </button>
        ) : (
          <span className="wmap-toggle wmap-toggle--spacer" />
        )}
        <button
          type="button"
          className="wmap-label"
          onClick={() => onSelect(node)}
        >
          <span className="wmap-type">{(node.node_type || "").toUpperCase()}</span>
          <span className="wmap-text">{node.label}</span>
          {direct ? (
            <Badge tone={sev === "CRITICAL" || sev === "HIGH" ? "danger" : "warn"}>
              {sev || "FINDING"} {node.finding_count}
            </Badge>
          ) : null}
          {!direct && desc ? (
            <span className="wmap-desc-badge" title="Descendant findings">
              ● {node.descendant_finding_count}
            </span>
          ) : null}
          {node.has_alert ? <span className="wmap-alert-dot" title="Has alert" /> : null}
        </button>
      </div>
      {hasKids && isOpen ? (
        <ul className="wmap-ul">
          {kids.map((child) => (
            <TreeNode
              key={child.id}
              node={child}
              childrenByParent={childrenByParent}
              nodesById={nodesById}
              expanded={expanded}
              toggle={toggle}
              onSelect={onSelect}
              selectedId={selectedId}
              threatOnly={threatOnly}
              filterType={filterType}
              query={query}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/**
 * Interactive Website Map / attack-surface tree.
 * Expects tree payload: { nodes, nodes_by_id, children_by_parent, root_ids }
 */
export default function WebsiteMap({
  tree,
  onSelectNode,
  selectedId,
  live = false,
}) {
  const nodesById = useMemo(() => tree?.nodes_by_id || {}, [tree]);
  const childrenByParent = useMemo(() => tree?.children_by_parent || {}, [tree]);
  const rootIds = useMemo(() => tree?.root_ids || [], [tree]);

  const [expanded, setExpanded] = useState(() => new Set());
  const [threatOnly, setThreatOnly] = useState(false);
  const [filterType, setFilterType] = useState("all");
  const [query, setQuery] = useState("");

  const roots = useMemo(
    () => rootIds.map((id) => nodesById[String(id)]).filter(Boolean),
    [rootIds, nodesById]
  );

  // Auto-expand roots and parent nodes so the full tree is visible as it grows

  React.useEffect(() => {
    if (!tree?.nodes?.length && !rootIds.length) return;
    setExpanded((prev) => {
      const next = new Set(prev);
      rootIds.forEach((id) => next.add(id));
      Object.keys(childrenByParent).forEach((pid) => {
        if (pid !== "root") next.add(Number(pid));
      });
      return next;
    });
  }, [tree?.nodes?.length, rootIds, childrenByParent]);


  const toggle = (id) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const expandAll = () => {
    setExpanded(new Set(Object.keys(nodesById).map((k) => Number(k))));
  };

  const collapseAll = () => setExpanded(new Set(rootIds));

  const showThreatPaths = () => {
    setThreatOnly(true);
    const next = new Set(rootIds);
    Object.values(nodesById).forEach((n) => {
      if ((n.finding_count || 0) > 0 || (n.descendant_finding_count || 0) > 0) {
        // expand ancestors
        let cur = n;
        while (cur) {
          next.add(cur.id);
          if (cur.parent_id != null) next.add(cur.parent_id);
          cur = cur.parent_id != null ? nodesById[String(cur.parent_id)] : null;
        }
      }
    });
    setExpanded(next);
  };

  if (!roots.length) {
    return (
      <div className="surface websec__panel muted">
        {live
          ? "Waiting for discovery events…"
          : "No attack-surface nodes yet. Run a scan to grow the Website Map."}
      </div>
    );
  }

  return (
    <div className="wmap">
      <div className="wmap-toolbar">
        <input
          className="field__input"
          placeholder="Search nodes…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <select
          className="field__input"
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
        >
          <option value="all">All types</option>
          <option value="domains">Domains</option>
          <option value="urls">URLs / paths</option>
          <option value="apis">APIs</option>
          <option value="ports">Ports</option>
        </select>
        <Button size="sm" onClick={expandAll}>
          Expand all
        </Button>
        <Button size="sm" onClick={collapseAll}>
          Collapse
        </Button>
        <Button size="sm" variant="primary" onClick={showThreatPaths}>
          Show threat paths
        </Button>
        <Button size="sm" onClick={() => setThreatOnly(false)}>
          Show all
        </Button>
        {live ? <Badge tone="ok">LIVE</Badge> : null}
      </div>
      <ul className="wmap-ul wmap-ul--root">
        {roots.map((node) => (
          <TreeNode
            key={node.id}
            node={node}
            childrenByParent={childrenByParent}
            nodesById={nodesById}
            expanded={expanded}
            toggle={toggle}
            onSelect={onSelectNode}
            selectedId={selectedId}
            threatOnly={threatOnly}
            filterType={filterType}
            query={query}
          />
        ))}
      </ul>
    </div>
  );
}

/** Merge a discovered/updated node into client tree state. */
export function upsertTreeNode(tree, node) {
  if (!node || !node.id) return tree || { nodes: [], nodes_by_id: {}, children_by_parent: {}, root_ids: [] };
  const nodes_by_id = { ...(tree?.nodes_by_id || {}), [String(node.id)]: node };
  const children_by_parent = { ...(tree?.children_by_parent || {}) };
  const pid = String(node.parent_id != null ? node.parent_id : "root");
  const list = new Set(children_by_parent[pid] || []);
  list.add(node.id);
  children_by_parent[pid] = Array.from(list);
  // Remove from other parents if moved (rare)
  Object.keys(children_by_parent).forEach((key) => {
    if (key === pid) return;
    children_by_parent[key] = (children_by_parent[key] || []).filter((id) => id !== node.id);
  });
  const root_ids =
    node.parent_id == null
      ? Array.from(new Set([...(tree?.root_ids || []), node.id]))
      : tree?.root_ids || children_by_parent.root || [];
  return {
    scan_id: tree?.scan_id,
    nodes: Object.values(nodes_by_id),
    nodes_by_id,
    children_by_parent,
    root_ids,
  };
}
