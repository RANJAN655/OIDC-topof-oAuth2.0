import {
  uuid,
  pgTable,
  varchar,
  text,
  boolean,
  timestamp,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

// =======================
// USERS TABLE
// =======================
export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),

  firstName: varchar("first_name", { length: 25 }),
  lastName: varchar("last_name", { length: 25 }),

  profileImageURL: text("profile_image_url"),

  email: varchar("email", { length: 322 }).notNull().unique(),
  emailVerified: boolean("email_verified").default(false).notNull(),

  password: text("password").notNull(),
  salt: text("salt").notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").$onUpdate(() => new Date()),
});

// =======================
// OAUTH CLIENTS TABLE
// =======================
export const oauthClients = pgTable("oauth_clients", {
  id: text("id").primaryKey(),

  name: text("name").notNull(),
  websiteUrl: text("website_url").notNull(),
  redirectUrl: text("redirect_uri").notNull(),

  clientId: text("client_id").notNull().unique(),
  clientSecret: text("client_secret").notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at")
    .defaultNow()
    .$onUpdate(() => new Date()),
});

// =======================
// AUTH CODES TABLE (IMPORTANT)
// =======================
export const authCodesTable = pgTable("auth_codes", {
  code: text("code").primaryKey(),

  userId:
    uuid(
      "user_id",
    ).notNull() /* Right now you only match type. Add foreign key reference: */,
  clientId: text("client_id").notNull(),

  redirectUrl: text("redirect_uri").notNull(),

  expiresAt: timestamp("expires_at").notNull(),
  used: boolean("used").default(false).notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// =======================
// RELATIONS (OPTIONAL)
// =======================
export const authCodesRelations = relations(authCodesTable, ({ one }) => ({
  user: one(usersTable, {
    fields: [authCodesTable.userId],
    references: [usersTable.id],
  }),

  client: one(oauthClients, {
    fields: [authCodesTable.clientId],
    references: [oauthClients.clientId],
  }),
}));




// schema/refreshTokens

export const refreshTokensTable = pgTable("refresh_tokens", {
  id: uuid("id").defaultRandom().primaryKey(),

  userId: text("user_id").notNull(),        // FK → users.id
  clientId: text("client_id").notNull(),    // FK → oauthClients.clientId

  tokenHash: text("token_hash").notNull(),  // SHA256 of token

  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),

  revoked: boolean("revoked").default(false),

  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow(),

  replacedByToken: text("replaced_by_token"), // optional (rotation tracking)
});
