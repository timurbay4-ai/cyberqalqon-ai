import type { MitreContext } from "../types/alerts";

export function MitreTags({ mitre, detailed = false }: { mitre: MitreContext; detailed?: boolean }) {
  if (mitre.ids.length === 0) return <span className="muted">No upstream mapping</span>;
  return (
    <div className="mitre-block">
      <div className="tag-list">
        {mitre.ids.map((id) => <span className="tag tag--mitre" key={id}>{id}</span>)}
      </div>
      {detailed && (
        <div className="mitre-details">
          <span><strong>Tactics</strong>{mitre.tactics.length ? mitre.tactics.join(" · ") : "Not supplied"}</span>
          <span><strong>Techniques</strong>{mitre.techniques.length ? mitre.techniques.join(" · ") : "Not supplied"}</span>
        </div>
      )}
    </div>
  );
}
