# M21 telemetry gap matrix

“No event observed” never means “zero security incidents.” Archive times are
event coverage, while systemd times describe collector availability.

## Day-by-day inventory

| Day | Archive coverage | Eligible / filtered / malformed | Ordering / duplicates | Gap classification |
|---|---|---:|---|---|
| 15 | 08:02:25.816 -> 00:00:00.573 | 93,127 / 116,951 / 50 | 118 event-ID regressions; 47 exact repeats | WSL boots end at 12:11 and 22:10, then resume 14:47 and 22:14: source/collector unavailable between boots. Largest ID gap 9,361.745 s is evidence of no archived event in that ID interval, not proof of no activity. |
| 16 | 00:00:01.689 -> 23:31:10.937 | 91,808 / 91,713 / 120 | 35 regressions; 15 exact repeats | WSL absent 10:51–14:35 and 22:35–22:40; after 23:31 no collector evidence until day 17. Largest ID gap 13,494.785 s. |
| 17 | 10:27:05.456 -> 00:00:00.713 | 109,133 / 105,206 / 66 | 81 regressions; 36 exact repeats | Day16 23:31 -> day17 10:27 is source offline/collector unavailable. Explicit Wazuh stop 11:32:57–11:39:18 and WSL boot gap 19:12–19:16. Largest ID gap 2,223 s. |
| 18 | 00:00:01.069 -> 00:00:01.106 | 142,880 / 135,421 / 164 | 86 regressions; 3 exact repeats | Continuous date coverage exists, but ordering regressions and largest 8,489 s ID gap mean continuity is not proven. Evidence is insufficient to infer missing source events. |
| 19 | 00:00:01.656 -> 22:24:33.269 | 28,173 / 19,194 / 1 | 18 regressions; 8 exact repeats | Wazuh explicitly stopped 01:38:49 and restarted 11:12:38. Largest ID gap 34,444.895 s. Collector stopped again 22:24:35. Terminal malformed item is the 305-byte NUL tail. |
| 20 neighbor | 07:13:56.507 -> at least 16:32:01.560 in captured prefix | not deeply rescanned | not claimed | Day19 22:24:38 -> day20 07:13:48 is WSL/source offline. Active captured prefix ends on a complete record; later bytes continued growing. |

## Generation boundaries

| Boundary | Observation | Classification |
|---|---|---|
| 15 -> 16 | Event-ID gap 0.198 s | No material boundary gap observed; not proof of source completeness. |
| 16 -> 17 | Event-ID gap 39,354.364 s | Source offline / collector unavailable, corroborated by boot journal. |
| 17 -> 18 | Event-ID gap 0.273 s | No material boundary gap observed. |
| 18 -> 19 | Event IDs regress 0.985 s while timestamps move forward | Inconsistent ID ordering; no exact cross-generation fingerprint duplicate. |
| 19 -> 20 | About 8 h 49 m between manager stop and next start | Source offline / collector unavailable. |

Across day 15–19 there are 934,007 physical segments, 933,606 valid JSON
objects, 395 invalid UTF-8 segments, five invalid JSON segments and one partial
terminal segment. There are 109 exact fingerprint repeats within generations
and zero exact cross-generation repeats. Source IDs repeat too frequently to
serve as unique identities.

## Day-19 terminal artifact

The last 305 bytes are allocated NUL bytes, not UTF-8 JSON, not a truncated
object with recoverable keys, and not the prefix of day 20. Classification:
**malformed_or_incomplete / unrecoverable_as_event**. It remains evidence and
must be counted separately, never delivered or synthesized.
