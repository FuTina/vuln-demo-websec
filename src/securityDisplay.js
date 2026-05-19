export function maskEmail(email) {
  const [user, domain] = String(email).split("@");
  if (!domain) return String(email);
  const head = user.slice(0, 2);
  const masked = head + "*".repeat(Math.max(1, user.length - 2));
  return `${masked}@${domain}`;
}

export function maskPhone(phone) {
  return String(phone).replace(/\d(?=(?:\D*\d){2,}\D*$)/g, "\u2022");
}

export function previewSQL(sql, params = []) {
  let index = 0;
  return sql.replace(/\?/g, () => {
    const value = params[index++];
    const safeValue = String(value ?? "").replace(/'/g, "''");
    return `'${safeValue}'`;
  });
}
