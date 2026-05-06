import { pgTable, text, timestamp } from "drizzle-orm/pg-core";

export const oauthClients = pgTable("oauth_clients", {
  id: text("id").primaryKey(),

  name: text("name").notNull(),
  websiteUrl: text("website_url").notNull(),
  redirectUrl: text("redirect_uri").notNull(),

  clientId: text("client_id").notNull().unique(),
  clientSecret: text("client_secret").notNull(),

  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});
