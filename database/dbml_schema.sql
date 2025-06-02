CREATE TABLE "users" (
  "id" int PRIMARY KEY,
  "username" varchar UNIQUE NOT NULL,
  "email" varchar UNIQUE NOT NULL,
  "password_hash" varchar NOT NULL,
  "function" varchar,
  "about_me" varchar,
  "is_active" boolean DEFAULT true,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp,
  "created_by" int,
  "updated_by" int
);

CREATE TABLE "roles" (
  "id" int PRIMARY KEY,
  "name" varchar UNIQUE NOT NULL,
  "description" varchar,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp,
  "created_by" int,
  "updated_by" int
);

CREATE TABLE "permissions" (
  "id" int PRIMARY KEY,
  "name" varchar UNIQUE NOT NULL,
  "description" varchar,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp,
  "created_by" int,
  "updated_by" int
);

CREATE TABLE "user_role_map" (
  "user_id" int NOT NULL,
  "role_id" int NOT NULL,
  PRIMARY KEY ("user_id", "role_id")
);

CREATE TABLE "role_permission_map" (
  "role_id" int NOT NULL,
  "permission_id" int NOT NULL,
  PRIMARY KEY ("role_id", "permission_id")
);

CREATE TABLE "posts" (
  "id" int PRIMARY KEY,
  "user_id" int NOT NULL,
  "title" varchar NOT NULL,
  "slug" varchar UNIQUE,
  "content" text NOT NULL,
  "is_published" boolean DEFAULT false,
  "visibility" varchar NOT NULL,
  "is_deleted" boolean DEFAULT false,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp,
  "created_by" int,
  "updated_by" int
);

CREATE TABLE "events" (
  "id" int PRIMARY KEY,
  "user_id" int NOT NULL,
  "title" varchar NOT NULL,
  "subtitle" varchar,
  "description" text,
  "event_date" timestamp NOT NULL,
  "location" varchar,
  "action_type_id" int NOT NULL,
  "visibility" varchar NOT NULL,
  "is_recurring" boolean DEFAULT false,
  "is_deleted" boolean DEFAULT false,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp,
  "created_by" int,
  "updated_by" int
);

CREATE TABLE "event_action_types" (
  "id" int PRIMARY KEY,
  "name" varchar UNIQUE NOT NULL,
  "description" varchar
);

CREATE TABLE "post_images" (
  "id" int PRIMARY KEY,
  "url" text NOT NULL,
  "post_id" int NOT NULL,
  "uploaded_by" int,
  "uploaded_at" timestamp DEFAULT (now())
);

CREATE TABLE "event_images" (
  "id" int PRIMARY KEY,
  "url" text NOT NULL,
  "event_id" int NOT NULL,
  "uploaded_by" int,
  "uploaded_at" timestamp DEFAULT (now())
);

CREATE TABLE "post_comments" (
  "id" int PRIMARY KEY,
  "post_id" int NOT NULL,
  "user_id" int NOT NULL,
  "content" text NOT NULL,
  "is_approved" boolean DEFAULT false,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp,
  "created_by" int,
  "updated_by" int
);

CREATE TABLE "event_comments" (
  "id" int PRIMARY KEY,
  "event_id" int NOT NULL,
  "user_id" int NOT NULL,
  "content" text NOT NULL,
  "is_approved" boolean DEFAULT false,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp,
  "created_by" int,
  "updated_by" int
);

CREATE TABLE "user_images" (
  "id" int PRIMARY KEY,
  "user_id" int NOT NULL,
  "url" text NOT NULL,
  "is_profile_picture" boolean DEFAULT true,
  "uploaded_at" timestamp DEFAULT (now())
);

CREATE TABLE "tags" (
  "id" int PRIMARY KEY,
  "name" varchar UNIQUE NOT NULL
);

CREATE TABLE "tag_map" (
  "tag_id" int NOT NULL,
  "entity_type" varchar NOT NULL,
  "entity_id" int NOT NULL,
  PRIMARY KEY ("tag_id", "entity_type", "entity_id")
);

CREATE TABLE "event_recurrence" (
  "id" int PRIMARY KEY,
  "event_id" int NOT NULL,
  "start_date" date NOT NULL,
  "end_date" date,
  "repeat_type" varchar NOT NULL,
  "interval" int DEFAULT 1,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp,
  "created_by" int,
  "updated_by" int
);

CREATE TABLE "event_recurrence_exceptions" (
  "id" int PRIMARY KEY,
  "recurrence_id" int NOT NULL,
  "original_date" date NOT NULL,
  "is_skipped" boolean DEFAULT false,
  "new_date" date,
  "new_location" varchar,
  "note" text,
  "created_at" timestamp DEFAULT (now()),
  "updated_at" timestamp,
  "created_by" int,
  "updated_by" int
);

CREATE TABLE "audit_log" (
  "id" int PRIMARY KEY,
  "user_id" int,
  "action" varchar NOT NULL,
  "table_name" varchar NOT NULL,
  "record_id" int NOT NULL,
  "change_summary" text,
  "created_at" timestamp DEFAULT (now())
);

ALTER TABLE "users" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("id");

ALTER TABLE "users" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "roles" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("id");

ALTER TABLE "roles" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "permissions" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("id");

ALTER TABLE "permissions" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "user_role_map" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "user_role_map" ADD FOREIGN KEY ("role_id") REFERENCES "roles" ("id");

ALTER TABLE "role_permission_map" ADD FOREIGN KEY ("role_id") REFERENCES "roles" ("id");

ALTER TABLE "role_permission_map" ADD FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id");

ALTER TABLE "posts" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "posts" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("id");

ALTER TABLE "posts" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "events" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "events" ADD FOREIGN KEY ("action_type_id") REFERENCES "event_action_types" ("id");

ALTER TABLE "events" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("id");

ALTER TABLE "events" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "post_images" ADD FOREIGN KEY ("post_id") REFERENCES "posts" ("id");

ALTER TABLE "post_images" ADD FOREIGN KEY ("uploaded_by") REFERENCES "users" ("id");

ALTER TABLE "event_images" ADD FOREIGN KEY ("event_id") REFERENCES "events" ("id");

ALTER TABLE "event_images" ADD FOREIGN KEY ("uploaded_by") REFERENCES "users" ("id");

ALTER TABLE "post_comments" ADD FOREIGN KEY ("post_id") REFERENCES "posts" ("id");

ALTER TABLE "post_comments" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "post_comments" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("id");

ALTER TABLE "post_comments" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "event_comments" ADD FOREIGN KEY ("event_id") REFERENCES "events" ("id");

ALTER TABLE "event_comments" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "event_comments" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("id");

ALTER TABLE "event_comments" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "user_images" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "tag_map" ADD FOREIGN KEY ("tag_id") REFERENCES "tags" ("id");

ALTER TABLE "event_recurrence" ADD FOREIGN KEY ("event_id") REFERENCES "events" ("id");

ALTER TABLE "event_recurrence" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("id");

ALTER TABLE "event_recurrence" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "event_recurrence_exceptions" ADD FOREIGN KEY ("recurrence_id") REFERENCES "event_recurrence" ("id");

ALTER TABLE "event_recurrence_exceptions" ADD FOREIGN KEY ("created_by") REFERENCES "users" ("id");

ALTER TABLE "event_recurrence_exceptions" ADD FOREIGN KEY ("updated_by") REFERENCES "users" ("id");

ALTER TABLE "audit_log" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "post_comments" ADD FOREIGN KEY ("post_id") REFERENCES "post_comments" ("id");
