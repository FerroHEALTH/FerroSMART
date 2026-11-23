- Breaking: the database schema ships as one baseline migration per area,
  which later releases change in place. The schema it creates is the same
  as before, but sqlx refuses a database migrated by an earlier release,
  because the files' checksums changed, so such a database is created fresh.
