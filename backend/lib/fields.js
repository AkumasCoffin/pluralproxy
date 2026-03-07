/**
 * Field mappings — JSON ↔ column names for wide tables.
 *
 * Mirrors the Python _ALTER_FIELD_MAP and _PROFILE_FIELD_MAP exactly.
 */

// Each entry: [groupName, jsonFieldName, columnPrefix, groupOrder, fieldOrder]
const ALTER_FIELD_MAP = [
  // ── Basic Info ──
  ['Basic Info', 'Name', 'name', 0, 0],
  ['Basic Info', 'Nicknames/Aliases', 'nicknames', 0, 1],
  ['Basic Info', 'Age', 'age', 0, 2],
  ['Basic Info', 'Gender', 'gender', 0, 3],
  ['Basic Info', 'Sexuality', 'sexuality', 0, 4],
  ['Basic Info', 'Presentation', 'presentation', 0, 5],
  ['Basic Info', 'Dominant emotion', 'dominant_emotion', 0, 6],
  // ── System Info ──
  ['System Info', 'Role', 'role', 1, 0],
  ['System Info', 'Subsystem/Group', 'subsystem', 1, 1],
  // ── Fronting & Switching ──
  ['Fronting & Switching', 'Fronting frequency', 'fronting_frequency', 2, 0],
  ['Fronting & Switching', 'Fronting signs', 'fronting_signs', 2, 1],
  ['Fronting & Switching', 'Dissociation level', 'dissociation_level', 2, 2],
  ['Fronting & Switching', 'Handoffs', 'handoffs', 2, 3],
  // ── Personality & Traits ──
  ['Personality & Traits', 'Personality description', 'personality_desc', 3, 0],
  ['Personality & Traits', 'Strengths', 'strengths', 3, 1],
  ['Personality & Traits', 'Struggles', 'struggles', 3, 2],
  ['Personality & Traits', 'Fears', 'fears', 3, 3],
  ['Personality & Traits', 'Values', 'f_values', 3, 4],
  ['Personality & Traits', 'Humor style', 'humor_style', 3, 5],
  ['Personality & Traits', 'Love language / comfort style', 'love_language', 3, 6],
  ['Personality & Traits', 'Energy level', 'energy_level', 3, 7],
  // ── Boundaries & Consent ──
  ['Boundaries & Consent', 'Hard boundaries', 'hard_boundaries', 4, 0],
  ['Boundaries & Consent', 'Soft boundaries', 'soft_boundaries', 4, 1],
  ['Boundaries & Consent', 'Consent reminders', 'consent_reminders', 4, 2],
  // ── Triggers & Warnings ──
  ['Triggers & Warnings', 'Known triggers', 'known_triggers', 5, 0],
  ['Triggers & Warnings', 'Alter Triggers', 'alter_triggers', 5, 1],
  ['Triggers & Warnings', 'Common sensitivities', 'common_sensitivities', 5, 2],
  ['Triggers & Warnings', 'Early warning signs', 'early_warning_signs', 5, 3],
  // ── Mental Health ──
  ['Mental Health', 'Diagnosis/known conditions', 'diagnosis', 6, 0],
  ['Mental Health', 'Coping strategies', 'coping_strategies', 6, 1],
  ['Mental Health', 'Crisis plan', 'crisis_plan', 6, 2],
  ['Mental Health', 'Therapist notes', 'therapist_notes', 6, 3],
  // ── Skills, Interests & Habits ──
  ['Skills, Interests & Habits', 'Skills', 'skills', 7, 0],
  ['Skills, Interests & Habits', 'Special interests', 'special_interests', 7, 1],
  ['Skills, Interests & Habits', 'Likes', 'likes', 7, 2],
  ['Skills, Interests & Habits', 'Dislikes', 'dislikes', 7, 3],
  ['Skills, Interests & Habits', 'Comfort items', 'comfort_items', 7, 4],
  ['Skills, Interests & Habits', 'Food/drink preferences', 'food_drink_prefs', 7, 5],
  ['Skills, Interests & Habits', 'Music/aesthetic', 'music_aesthetic', 7, 6],
  ['Skills, Interests & Habits', 'Shows/games they like', 'shows_games', 7, 7],
  // ── Relationships ──
  ['Relationships', 'Closest alters', 'closest_alters', 8, 0],
  ['Relationships', 'Tension/conflict', 'tension_conflict', 8, 1],
  ['Relationships', 'Caretakers', 'caretakers', 8, 2],
  ['Relationships', 'External relationships', 'external_rels', 8, 3],
  // ── Communication ──
  ['Communication', 'Internal Communication', 'internal_comm', 9, 0],
  ['Communication', 'Communication Method', 'comm_method', 9, 1],
  ['Communication', 'Tone Use', 'tone_use', 9, 2],
  // ── Notes ──
  ['Notes', 'General notes', 'general_notes', 10, 0],
  ['Notes', 'Session notes', 'session_notes', 10, 1],
  ['Notes', 'Goals', 'goals', 10, 2],
  ['Notes', 'To-do / follow-up', 'todo_followup', 10, 3],
  // ── Quick Summary ──
  ['Quick Summary', '1\u20133 sentence summary', 'summary', 11, 0],
];

// Derived lookups

// (groupName, fieldName) → columnPrefix
const ALTER_JSON_TO_COL = new Map();
for (const [g, f, col] of ALTER_FIELD_MAP) {
  ALTER_JSON_TO_COL.set(`${g}\0${f}`, col);
}

// columnPrefix → { groupName, fieldName, groupOrder, fieldOrder }
const ALTER_COL_TO_JSON = new Map();
for (const [g, f, col, go, fo] of ALTER_FIELD_MAP) {
  ALTER_COL_TO_JSON.set(col, { groupName: g, fieldName: f, groupOrder: go, fieldOrder: fo });
}

// All column prefixes
const ALTER_COL_PREFIXES = ALTER_FIELD_MAP.map(([, , col]) => col);

// ── Profile fields ───────────────────────────────────────────────────

// [jsonKey, columnPrefix]
const PROFILE_FIELD_MAP = [
  ['Age', 'age'],
  ['Pronouns', 'pronouns'],
  ['Gender', 'gender'],
  ['Sexuality', 'sexuality'],
  ['Communication', 'communication'],
  ['Personality', 'personality'],
  ['Boundaries', 'boundaries'],
  ['Triggers', 'triggers'],
  ['Bio', 'bio'],
];

const PROFILE_JSON_TO_COL = new Map();
const PROFILE_COL_TO_JSON = new Map();
for (const [jsonKey, col] of PROFILE_FIELD_MAP) {
  PROFILE_JSON_TO_COL.set(jsonKey, col);
  PROFILE_COL_TO_JSON.set(col, jsonKey);
}

module.exports = {
  ALTER_FIELD_MAP,
  ALTER_JSON_TO_COL,
  ALTER_COL_TO_JSON,
  ALTER_COL_PREFIXES,
  PROFILE_FIELD_MAP,
  PROFILE_JSON_TO_COL,
  PROFILE_COL_TO_JSON,
};
