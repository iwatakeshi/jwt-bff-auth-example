# Migration `20201030021308-make-username-name-unique-and-index-it`

This migration has been generated by Takeshi at 10/29/2020, 8:13:08 PM.
You can check out the [state of the schema](./schema.prisma) after the migration.

## Database Steps

```sql
CREATE UNIQUE INDEX "User.username_unique" ON "User"("username")

CREATE INDEX "User.id_username_index" ON "User"("id", "username")
```

## Changes

```diff
diff --git schema.prisma schema.prisma
migration 20201030020636-make-token-optional..20201030021308-make-username-name-unique-and-index-it
--- datamodel.dml
+++ datamodel.dml
@@ -2,17 +2,19 @@
 // learn more about it in the docs: https://pris.ly/d/prisma-schema
 datasource db {
   provider = "sqlite"
-  url = "***"
+  url = "***"
 }
 generator client {
   provider = "prisma-client-js"
 }
 model User {
   id       Int     @id @default(autoincrement())
-  username String
+  username String  @unique
   password String
   token    String?
+
+  @@index([id, username])
 }
```


