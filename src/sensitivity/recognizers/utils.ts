/**
 * Executes a global regex against content and returns all matches.
 */
export function execAll(pattern: RegExp, content: string): RegExpExecArray[] {
  const matches: RegExpExecArray[] = [];
  let m;
  while ((m = pattern.exec(content)) !== null) {
    matches.push(m);
  }
  return matches;
}
