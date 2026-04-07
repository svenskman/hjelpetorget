// VERSION: 0.2.0
'use strict';

const BAD_WORDS = [
  'faen','helvete','jævla','dritt','pikk','fitte','kuk','rasist','neger','pakkis',
  'homo','ludder','hore','fan','jävla','skit','fuck','shit','bitch','asshole',
  'nigger','kill','rape','bombe','sprengstoff','narkotika','heroin','kokain',
];

const CONTACT_PATTERNS = [
  /\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b/i,
  /\b(\+?47)?[\s.-]?[2-9]\d{7}\b/,
  /https?:\/\/[^\s]+/i,
  /\bwww\.[^\s]+\.[a-z]{2,}/i,
  /\b(snap|snapchat|instagram|telegram|signal|whatsapp)\b/i,
];

const DANGER_PATTERNS = [
  /\b(bomb|eksplosiv|skyt|drep|mord|terror)\b/i,
  /\b(kjøp\s+sex|eskorte|happy\s+ending)\b/i,
  /\b(bitcoin|western\s+union|nigeria|lotto|gevinst)\b/i,
];

function analyzeContent(title, body) {
  const text = (title + ' ' + body).toLowerCase();
  const reasons = [];
  let score = 0;

  for (const w of BAD_WORDS) {
    if (new RegExp('\\b' + w + '\\b', 'i').test(text)) {
      reasons.push('BAD_WORD:' + w); score += 3;
    }
  }
  for (const p of CONTACT_PATTERNS) {
    if (p.test(text)) {
      reasons.push('CONTACT_INFO:' + (text.match(p) || [''])[0].slice(0, 30));
      score += 2;
    }
  }
  for (const p of DANGER_PATTERNS) {
    if (p.test(text)) {
      reasons.push('DANGEROUS:' + (text.match(p) || [''])[0].slice(0, 30));
      score += 5;
    }
  }

  const letters = text.replace(/[^a-zA-ZæøåÆØÅ]/g, '');
  if (letters.length > 20 && (letters.match(/[A-ZÆØÅ]/g) || []).length / letters.length > 0.6) {
    reasons.push('SPAM:CAPS_LOCK'); score += 1;
  }
  if (/(.)\1{4,}/.test(title + body)) { reasons.push('SPAM:REPETITION'); score += 1; }

  return {
    flagged:  score > 0,
    reasons:  [...new Set(reasons)],
    score,
    severity: score >= 5 ? 'high' : score >= 2 ? 'medium' : 'low',
  };
}

module.exports = { analyzeContent };
