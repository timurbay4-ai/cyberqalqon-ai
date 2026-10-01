import { getMitreTechniqueInfo } from '@/utils';

interface MitreTagListProps {
  ids: string[];
  techniques?: string[];
}

/**
 * MitreTagList — renders MITRE ATT&CK technique IDs as accessible links.
 *
 * Each tag links to the official MITRE ATT&CK website.
 * Technique names are from a local lookup — not claimed as confirmed or AI-verified.
 * Missing technique names display the raw ID without fabrication.
 *
 * Note: these are technique identifiers observed in alerts.
 * Their accuracy depends on the Wazuh rule that produced the alert.
 */
export function MitreTagList({ ids, techniques }: MitreTagListProps) {
  if (!ids || ids.length === 0) {
    return <span className="text-muted text-xs">No MITRE identifiers</span>;
  }

  return (
    <div className="mitre-tag-list" aria-label="MITRE ATT&CK technique identifiers">
      {ids.map((id, index) => {
        const info = getMitreTechniqueInfo(id);
        const techniqueName = techniques?.[index] ?? info.name;
        return (
          <a
            key={id}
            href={info.url}
            target="_blank"
            rel="noreferrer noopener"
            className="mitre-tag"
            aria-label={`MITRE ATT&CK technique ${id}: ${techniqueName}. Opens in new tab.`}
            title={techniqueName}
          >
            {id}
          </a>
        );
      })}
    </div>
  );
}
