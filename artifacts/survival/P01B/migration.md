# P01B migration and rollback

Migration is opt-in:

1. Render the base and metadata-safe Compose files together.
2. Declare exact positive evidence and metric file counts, then run the strict metadata gate over
   those explicit selections.
3. Verify the clean pinned XNode generator and exact P01 expectations fixture.
4. Apply the 24-hour operational and 7-day metrics deletion lifecycle; generate and immediately
   revalidate a local receipt against a protected canonical inventory outside Git. The inventory
   must pin the canonical root, exact nonempty relative paths and exact count; the receipt binds
   identity hashes, size, mtime and content SHA-256.
5. Require a closed Mr. X break-glass receipt after exceptional raw-log access.

The metadata-safe UAT overlay changes the unexposed VLESS container listener to `8443` so all
capabilities can be dropped. Do not use this isolated topology as a public relay profile.

If protected retention inventory/receipt/root inputs are absent, retain the explicit `not-run`
status. Do not convert it to a passing boolean.

Rollback removes the overlay and returns to the compatible default profile. That rollback also
removes the metadata privacy release claim; it must not be described as metadata-safe. Previously
captured raw logs must still be deleted and verified rather than retained because of rollback.
