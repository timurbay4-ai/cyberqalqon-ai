# M17 retention interaction

Live policy remains 30 days and 100,000 rows. No cap, schema or protected
evidence rule changed.

Every insert increments the durable retained counter inside the same
`BEGIN IMMEDIATE` transaction. At capacity, the M17 fast path removes only the
oldest unprotected rows, excluding the just-inserted event. A full age sweep
and exact count reconciliation still runs on the five-minute boundary.
Case-event links, incident pins, case evidence references and alert-linked
events remain protected. If protection prevents deletion, the store reports
`OVER_LIMIT_PROTECTED` rather than deleting evidence.

Historical events older than 30 days are rejected as outside the approved
window. A newly accepted in-window historical record may displace the oldest
unprotected row at cap. Therefore replay success is not equivalent to net row
growth or permanent retention.

The disposable 50,000-row A/B test preserved the cap, durable counter,
`quick_check=ok` and zero foreign-key errors for both implementations. The
optimized median was 144.854 ms versus 255.774 ms legacy. Raising the live cap
or disabling retention was not tested or authorized.
