-- ============================================================
-- Rift central server — 006: drop DM reactions
-- ============================================================
-- Central DMs are the first-contact tier: you meet someone here, exchange a few
-- messages, and move to a shared server. Everything on this tier costs quota
-- and runs on infrastructure the project pays for, so it carries only what
-- first contact needs. Reactions are not that. They stay on self-hosted servers
-- (`message_reactions` / `dm_message_reactions` there), where the conversation
-- someone would want to react to actually lives.
--
-- Dropping the table takes its policies, grants and index with it. Migrations
-- 001 and 002 no longer create it, so a database provisioned from scratch never
-- has it; this file is for the one that already does.

DROP TABLE IF EXISTS dm_message_reactions;
