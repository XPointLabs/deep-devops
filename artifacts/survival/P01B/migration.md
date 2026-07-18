# P01B migration and rollback

Migration is opt-in:

1. Render the base and metadata-safe Compose files together.
2. Declare exact positive evidence and metric file counts, then run the strict metadata gate over
   those explicit selections.
3. Verify the clean pinned XNode generator and exact P01 expectations fixture.
4. Apply the 24-hour operational and 7-day metrics deletion lifecycle; generate and immediately
   revalidate a local receipt bound to the exact archive set and filesystem mtimes.
5. Require a closed Mr. X break-glass receipt after exceptional raw-log access.

The metadata-safe UAT overlay changes the unexposed VLESS container listener to `8443` so all
capabilities can be dropped. Do not use this isolated topology as a public relay profile.

Rollback removes the overlay and returns to the compatible default profile. That rollback also
removes the metadata privacy release claim; it must not be described as metadata-safe. Previously
captured raw logs must still be deleted and verified rather than retained because of rollback.
