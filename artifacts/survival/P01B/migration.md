# P01B migration and rollback

Migration is opt-in:

1. Render the base and metadata-safe Compose files together.
2. Run the strict metadata gate over explicit sanitized evidence and metrics exports.
3. Verify the clean pinned XNode generator and exact P01 expectations fixture.
4. Apply the 24-hour operational and 7-day metrics deletion lifecycle.
5. Require a closed Mr. X break-glass receipt after exceptional raw-log access.

Rollback removes the overlay and returns to the compatible default profile. That rollback also
removes the metadata privacy release claim; it must not be described as metadata-safe. Previously
captured raw logs must still be deleted and verified rather than retained because of rollback.
