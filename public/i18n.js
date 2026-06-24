(function () {
  const storageKey = "dbsec.language";
  const fallbackLanguage = "en";
  const supportedLanguages = ["en", "de"];

  const de = {
    "Audit Logging - Database Security Playground": "Audit Logging - Database Security Playground",
    "Config": "Konfiguration",
    "Data Masking - Database Security Playground": "Data Masking - Database Security Playground",
    "Database Security Playground": "Database Security Playground",
    "Network Exposure - Database Security Playground": "Network Exposure - Database Security Playground",
    "Secure Configuration - Database Security Playground": "Secure Configuration - Database Security Playground",
    "SQL Injection - Database Security Playground": "SQL Injection - Database Security Playground",
    "XSS - Database Security Playground": "XSS - Database Security Playground",

    "Security training lab": "Security-Trainingslabor",
    "Database Security Playground home": "Database Security Playground Startseite",
    "Language": "Sprache",
    "Main navigation": "Hauptnavigation",
    "Overview": "Übersicht",
    "Guided Demo": "Geführte Demo",
    "Show how six database controls turn an insecure baseline into a safer architecture.": "Zeigt, wie sechs Datenbankkontrollen eine unsichere Ausgangslage in eine sicherere Architektur verwandeln.",
    "Current risk": "Aktuelles Risiko",
    "Current demo risk score": "Aktueller Demo-Risikowert",
    "Low risk": "Niedriges Risiko",
    "Medium Risk": "Mittleres Risiko",
    "High Risk": "Hohes Risiko",
    "Low Risk": "Niedriges Risiko",
    "Next required step": "Nächster Schritt",
    "Ready for demo": "Bereit für die Demo",
    "Start demo": "Demo starten",
    "Demo Flow": "Demo-Ablauf",
    "Security Demo Walkthrough": "Security Demo Walkthrough",
    "Bypass login, then fix with prepared statements.": "Login umgehen, dann mit Prepared Statements absichern.",
    "Inject HTML, then fix with output encoding.": "HTML einschleusen, dann mit Output Encoding absichern.",
    "Compare raw vs role-scoped data.": "Rohdaten mit rollenbeschränkten Daten vergleichen.",
    "Trigger events and inspect evidence.": "Ereignisse auslösen und Nachweise prüfen.",
    "Make DB private.": "Datenbank privat machen.",
    "Review hardened config.": "Gehärtete Konfiguration prüfen.",
    "Open": "Öffnen",
    "Close": "Schließen",
    "Executive summary": "Management-Zusammenfassung",
    "Supporting information": "Zusätzliche Informationen",

    "Step 1: SQL Injection": "Schritt 1: SQL Injection",
    "Step 2: XSS": "Schritt 2: XSS",
    "Step 3: Data Masking": "Schritt 3: Data Masking",
    "Step 4: Audit Logging": "Schritt 4: Audit Logging",
    "Step 5: Network Exposure": "Schritt 5: Network Exposure",
    "Step 6: Secure Configuration": "Schritt 6: Secure Configuration",
    "Step 1/6": "Schritt 1/6",
    "Step 2/6": "Schritt 2/6",
    "Step 3/6": "Schritt 3/6",
    "Step 4/6": "Schritt 4/6",
    "Step 5/6": "Schritt 5/6",
    "Step 6/6": "Schritt 6/6",
    "Step 1": "Schritt 1",
    "Step 2": "Schritt 2",
    "Step 3": "Schritt 3",
    "Step 4": "Schritt 4",
    "Step 5": "Schritt 5",
    "Step 6": "Schritt 6",
    "Complete": "Abgeschlossen",
    "All exercises complete": "Alle Übungen abgeschlossen",
    "Closing summary": "Abschlussübersicht",
    "Review the final overview.": "Abschlussübersicht prüfen.",
    "Guided lab": "Geführtes Lab",
    "Learning progress": "Lernfortschritt",
    "Progress": "Fortschritt",
    "Risk": "Risiko",
    "Next:": "Weiter:",
    "Lab options": "Lab-Optionen",
    "Back to overview": "Zur Übersicht",
    "Reset lab": "Lab zurücksetzen",
    "Open a specific exercise": "Bestimmte Übung öffnen",
    "Direct exercise access": "Direkter Zugriff auf Übungen",
    "Risk summary": "Risikoübersicht",
    "Enabled protections": "Aktive Schutzmaßnahmen",
    "Active risks": "Aktive Risiken",
    "No controls enabled": "Keine Kontrollen aktiviert",
    "No active demo risks": "Keine aktiven Demo-Risiken",
    "Security category coverage": "Abdeckung der Sicherheitskategorien",
    "Compact lab status": "Kompakter Lab-Status",
    "Current guided exercise": "Aktuelle geführte Übung",
    "Guided lab progress": "Fortschritt im geführten Lab",
    "Baseline actions": "Baseline-Aktionen",
    "Open navigation menu": "Navigation öffnen",
    "Close navigation menu": "Navigation schließen",
    "Mobile exercise navigation": "Mobile Übungsnavigation",

    "Scenario": "Szenario",
    "Action": "Aktion",
    "Result": "Ergebnis",
    "Why": "Warum",
    "Why does this matter?": "Warum ist das wichtig?",
    "Security Impact": "Sicherheitsauswirkung",
    "Security impact": "Sicherheitsauswirkung",
    "Security takeaway": "Security Takeaway",
    "Operational takeaway": "Operativer Takeaway",
    "Mentor brief": "Mentor-Briefing",
    "Task, why, and success": "Aufgabe, Grund und Erfolg",
    "Task": "Aufgabe",
    "Why it matters": "Warum es wichtig ist",
    "Success looks like": "Erfolg sieht so aus",
    "Next action": "Nächste Aktion",
    "Need a hint?": "Brauchst du einen Hinweis?",
    "Show guide tip": "Guide-Hinweis anzeigen",
    "Hide guide": "Guide ausblenden",
    "Guided lab complete": "Geführtes Lab abgeschlossen",
    "Return to Overview": "Zurück zur Übersicht",
    "Open Overview": "Übersicht öffnen",
    "Finish on Overview": "In der Übersicht abschließen",
    "Finish flow": "Ablauf abschließen",
    "All guided controls are complete. Use the overview as the closing summary.": "Alle geführten Kontrollen sind abgeschlossen. Nutze die Übersicht als Abschluss.",
    "All steps are complete. Review the overview as your closing summary.": "Alle Schritte sind abgeschlossen. Prüfe die Übersicht als Abschluss.",
    "The lab is complete. The overview is now the closing summary.": "Das Lab ist abgeschlossen. Die Übersicht ist jetzt die Abschlusszusammenfassung.",
    "Return to the overview for the closing summary.": "Kehre für die Abschlusszusammenfassung zur Übersicht zurück.",
    "Review lab summary": "Lab-Zusammenfassung prüfen",

    "Vulnerable": "Verwundbar",
    "Protected": "Geschützt",
    "Protected mode": "Geschützter Modus",
    "Unsafe": "Unsicher",
    "Safe": "Sicher",
    "Ready": "Bereit",
    "Review": "Prüfen",
    "Resolved": "Gelöst",
    "Critical": "Kritisch",
    "Build": "Erstellen",
    "Enabled": "Aktiviert",
    "Restricted": "Eingeschränkt",
    "Unrestricted": "Uneingeschränkt",
    "Logged": "Protokolliert",
    "Unlogged": "Nicht protokolliert",
    "Segmented": "Segmentiert",
    "Exposed": "Exponiert",
    "Hardened": "Gehärtet",
    "High risk configuration": "Konfiguration mit hohem Risiko",
    "Medium risk configuration": "Konfiguration mit mittlerem Risiko",
    "Low risk configuration": "Konfiguration mit niedrigem Risiko",
    "Build configuration": "Konfiguration erstellen",

    "SQL Injection Login Bypass": "SQL Injection Login-Bypass",
    "A login form should prove that prepared statements keep user input out of SQL query logic.": "Ein Login-Formular zeigt, dass Prepared Statements Benutzereingaben von der SQL-Logik trennen.",
    "Attempt a login": "Login versuchen",
    "SQL mode": "SQL-Modus",
    "Credentials": "Zugangsdaten",
    "Username": "Benutzername",
    "Password": "Passwort",
    "Demo input": "Demo-Eingabe",
    "Wrong password": "Falsches Passwort",
    "Valid login": "Gültiger Login",
    "Run login check": "Login prüfen",
    "Reset": "Zurücksetzen",
    "Evidence from the login check": "Nachweis aus der Login-Prüfung",
    "Generated query": "Erzeugte Abfrage",
    "Choose a mode and run the login check.": "Wähle einen Modus und führe die Login-Prüfung aus.",
    "Run the login check with the current input.": "Führe die Login-Prüfung mit der aktuellen Eingabe aus.",
    "No data returned yet.": "Noch keine Daten zurückgegeben.",
    "No rows returned.": "Keine Zeilen zurückgegeben.",
    "Access granted": "Zugriff erlaubt",
    "Access denied": "Zugriff verweigert",
    "Data leaked": "Daten offengelegt",
    "Protected by prepared statement": "Durch Prepared Statement geschützt",
    "The input was treated as values. The login did not match.": "Die Eingabe wurde als Wert behandelt. Der Login passte nicht.",
    "The injected condition changed the WHERE clause and returned multiple users.": "Die eingeschleuste Bedingung änderte die WHERE-Klausel und gab mehrere Benutzer zurück.",
    "The comment marker bypassed the password condition.": "Der Kommentar-Marker umging die Passwortbedingung.",
    "No user matched the supplied username and password.": "Kein Benutzer passte zu Benutzername und Passwort.",
    "Query boundary": "Abfragegrenze",
    "User input": "Benutzereingabe",
    "Vulnerable SQL": "Verwundbares SQL",
    "Input becomes logic": "Eingabe wird zu Logik",
    "Password check skipped": "Passwortprüfung übersprungen",
    "Prepared statement keeps value separate": "Prepared Statement hält Werte getrennt",
    "Prepared statements prevent user-controlled query manipulation.": "Prepared Statements verhindern benutzergesteuerte Query-Manipulation.",
    "No destructive payloads are needed to demonstrate the risk: read-only login bypass is enough.": "Für die Demonstration sind keine destruktiven Payloads nötig: Ein lesender Login-Bypass reicht aus.",
    "Make parameterized queries a default code review requirement.": "Mache parametrisierte Abfragen zur Standardanforderung im Code Review.",
    "Validation and rate limits help, but they do not replace fixed SQL structure.": "Validierung und Rate Limits helfen, ersetzen aber keine feste SQL-Struktur.",
    "Database Security Playground - SQL Injection module.": "Database Security Playground - SQL Injection Modul.",

    "Cross-Site Scripting Rendering": "Cross-Site-Scripting Rendering",
    "Comments should prove that safe output APIs keep untrusted markup as visible text.": "Kommentare zeigen, dass sichere Ausgabe-APIs nicht vertrauenswürdiges Markup als sichtbaren Text behandeln.",
    "Post a comment": "Kommentar posten",
    "Rendering mode": "Rendering-Modus",
    "Comment": "Kommentar",
    "Demo payload": "Demo-Payload",
    "HTML": "HTML",
    "Link": "Link",
    "Download": "Download",
    "Plain text": "Nur Text",
    "Post comment": "Kommentar posten",
    "Evidence from browser rendering": "Nachweis aus dem Browser-Rendering",
    "Simulated CSP: report-only": "Simulierte CSP: nur Bericht",
    "CSP is shown as a teaching badge; rendering behavior is controlled by the switch.": "CSP wird als Lernhinweis gezeigt; das Rendering-Verhalten steuert der Schalter.",
    "Comment output": "Kommentar-Ausgabe",
    "Rendering API": "Rendering-API",
    "Avoid for untrusted input": "Für nicht vertrauenswürdige Eingaben vermeiden",
    "Preferred for plain text": "Bevorzugt für reinen Text",
    "DOM effect": "DOM-Effekt",
    "DOM effect: active HTML": "DOM-Effekt: aktives HTML",
    "DOM effect: plain text": "DOM-Effekt: reiner Text",
    "Markup is parsed into live HTML nodes.": "Markup wird in aktive HTML-Knoten geparst.",
    "The browser parses the comment as HTML, so an attacker-controlled link or download action becomes part of the page.": "Der Browser parst den Kommentar als HTML; dadurch wird ein angreifergesteuerter Link oder Download Teil der Seite.",
    "The browser receives the comment as text, so angle brackets are displayed instead of executed as markup.": "Der Browser erhält den Kommentar als Text; spitze Klammern werden angezeigt statt als Markup ausgeführt.",
    "Post one of the red demo payloads to compare clickable markup with safe text.": "Poste einen der roten Demo-Payloads, um klickbares Markup mit sicherem Text zu vergleichen.",
    "Use one of the red demo payloads to show the difference between clickable markup and safe text.": "Nutze einen der roten Demo-Payloads, um den Unterschied zwischen klickbarem Markup und sicherem Text zu zeigen.",
    "Vulnerable: markup became active": "Verwundbar: Markup wurde aktiv",
    "Protected: output stayed text": "Geschützt: Ausgabe blieb Text",
    "parsed the comment as HTML. For untrusted comments, this API gives attacker-controlled text a chance to become page structure.": "parste den Kommentar als HTML. Bei nicht vertrauenswürdigen Kommentaren kann angreifergesteuerter Text so zur Seitenstruktur werden.",
    "inserted the same input as text. Tags, links, and download attributes are displayed instead of becoming active UI.": "fügte dieselbe Eingabe als Text ein. Tags, Links und Download-Attribute werden angezeigt, statt aktive UI zu werden.",
    "Browser rendering": "Browser-Rendering",
    "Comment text": "Kommentartext",
    "Active markup": "Aktives Markup",
    "Visible text": "Sichtbarer Text",
    "Encode output by default": "Ausgabe standardmäßig encodieren",
    "innerHTML interprets markup": "innerHTML interpretiert Markup",
    "When untrusted input is assigned to": "Wenn nicht vertrauenswürdige Eingabe an",
    "the browser parses tags as page structure. Links and downloads become active UI.": "übergeben wird, parst der Browser Tags als Seitenstruktur. Links und Downloads werden aktive UI.",
    "textContent treats input as text": "textContent behandelt Eingaben als Text",
    "When assigned to": "Wenn an",
    "angle brackets remain characters, not HTML.": "übergeben, bleiben spitze Klammern Zeichen und werden nicht zu HTML.",
    "Output encoding prevents injection": "Output Encoding verhindert Injection",
    "Encoding or safe rendering ensures user content is displayed in the intended context only.": "Encoding oder sicheres Rendering stellt sicher, dass Benutzerinhalte nur im vorgesehenen Kontext angezeigt werden.",
    "Default to safe text output for user-generated content.": "Nutze standardmäßig sichere Textausgabe für nutzergenerierte Inhalte.",
    "If rich text is required, sanitize it with a proven library and pair it with CSP.": "Wenn Rich Text nötig ist, bereinige ihn mit einer bewährten Bibliothek und kombiniere ihn mit CSP.",
    "Use safe rendering APIs as the normal implementation path.": "Nutze sichere Rendering-APIs als normalen Implementierungsweg.",
    "Keep risky rendering APIs narrow, reviewed, and covered by tests.": "Halte riskante Rendering-APIs eng begrenzt, geprüft und durch Tests abgedeckt.",
    "Database Security Playground - XSS module.": "Database Security Playground - XSS Modul.",

    "Role-Based Access & Data Masking": "Rollenbasierter Zugriff & Data Masking",
    "Customer records should prove that authorization and masking solve different exposure problems.": "Kundendaten zeigen, dass Autorisierung und Maskierung unterschiedliche Offenlegungsprobleme lösen.",
    "Select a role": "Rolle auswählen",
    "Role": "Rolle",
    "Select role": "Rolle auswählen",
    "Guest": "Gast",
    "Limited access": "Begrenzter Zugriff",
    "Operational data": "Operative Daten",
    "Analyst": "Analyst",
    "Business data": "Geschäftsdaten",
    "Administrator": "Administrator",
    "Full access": "Vollzugriff",
    "Security state": "Sicherheitszustand",
    "Enable RBAC + masking": "RBAC + Masking aktivieren",
    "Protected mode enabled": "Geschützter Modus aktiv",
    "Evidence from the selected role": "Nachweis für die ausgewählte Rolle",
    "Before and after data view": "Vorher-Nachher-Datenansicht",
    "Raw Data": "Rohdaten",
    "Protected Data": "Geschützte Daten",
    "Raw Data - Before protection": "Rohdaten - vor Schutz",
    "Protected Data - After RBAC + masking": "Geschützte Daten - nach RBAC + Masking",
    "Records": "Datensätze",
    "Fields": "Felder",
    "Boundary": "Grenze",
    "Role scoped": "Rollenbeschränkt",
    "All records": "Alle Datensätze",
    "Masked": "Maskiert",
    "Raw values": "Rohwerte",
    "Enforced": "Erzwungen",
    "Masking alone is not authorization": "Masking allein ist keine Autorisierung",
    "RBAC is disabled, so every role can reach the underlying records. Masking may hide some fields, but it does not prove the user is allowed to access the data.": "RBAC ist deaktiviert; dadurch kann jede Rolle auf die zugrunde liegenden Datensätze zugreifen. Masking kann einzelne Felder verbergen, beweist aber keine Zugriffsberechtigung.",
    "Raw Data: sensitive customer information is fully exposed.": "Rohdaten: sensible Kundendaten sind vollständig sichtbar.",
    "Raw Data before protection: the same role could see the unprotected dataset.": "Rohdaten vor Schutz: dieselbe Rolle konnte den ungeschützten Datensatz sehen.",
    "Protected Data: RBAC limits records and masking reduces sensitive fields.": "Geschützte Daten: RBAC begrenzt Datensätze und Masking reduziert sensible Felder.",
    "Customer": "Kunde",
    "Segment": "Segment",
    "Revenue": "Umsatz",
    "Email": "E-Mail",
    "Phone": "Telefon",
    "Notes": "Notizen",
    "Role policy": "Rollenrichtlinie",
    "Masked contact data": "Maskierte Kontaktdaten",
    "Hidden by RBAC": "Durch RBAC verborgen",
    "RBAC enforced": "RBAC erzwungen",
    "RBAC disabled": "RBAC deaktiviert",
    "Masking enabled": "Masking aktiviert",
    "Masking disabled": "Masking deaktiviert",
    "Authentication": "Authentifizierung",
    "Authorization": "Autorisierung",
    "Authentication proves who the user is. It does not automatically grant access to every field.": "Authentifizierung beweist, wer der Nutzer ist. Sie gewährt nicht automatisch Zugriff auf jedes Feld.",
    "Authorization decides which records and fields the authenticated role can access.": "Autorisierung entscheidet, auf welche Datensätze und Felder die authentifizierte Rolle zugreifen darf.",
    "Masking": "Masking",
    "Masking reduces displayed sensitivity only for fields the role is allowed to receive.": "Masking reduziert die sichtbare Sensibilität nur bei Feldern, die die Rolle erhalten darf.",
    "Least privilege": "Least Privilege",
    "Least privilege returns only the data needed for the current role and task.": "Least Privilege liefert nur die Daten, die für die aktuelle Rolle und Aufgabe nötig sind.",
    "Least privilege limits blast radius: authorize first, then minimize and mask returned data.": "Least Privilege begrenzt den Schaden: erst autorisieren, dann zurückgegebene Daten minimieren und maskieren.",
    "Separate authorization policy from presentation masking.": "Trenne Autorisierungsrichtlinie von Anzeige-Masking.",
    "Least privilege limits blast radius.": "Least Privilege begrenzt den Schaden.",
    "Authorize first, then minimize and mask the data returned.": "Erst autorisieren, dann zurückgegebene Daten minimieren und maskieren.",
    "Masking reduces displayed sensitivity, but RBAC decides whether the data should be returned at all.": "Masking reduziert sichtbare Sensibilität, aber RBAC entscheidet, ob Daten überhaupt zurückgegeben werden.",
    "Database Security Playground - role and data masking module.": "Database Security Playground - Rollen- und Data-Masking-Modul.",

    "Database Audit Logging": "Database Audit Logging",
    "Suspicious database actions should prove whether the team has investigation evidence.": "Verdächtige Datenbankaktionen sollen zeigen, ob das Team Untersuchungsnachweise hat.",
    "Trigger database-relevant actions": "Datenbankrelevante Aktionen auslösen",
    "Audit logging mode": "Audit-Logging-Modus",
    "Logging off": "Logging aus",
    "Logging on": "Logging an",
    "Login": "Login",
    "Normal authenticated session.": "Normale authentifizierte Sitzung.",
    "Failed login": "Fehlgeschlagener Login",
    "Failed authentication attempt.": "Fehlgeschlagener Authentifizierungsversuch.",
    "Read data": "Daten lesen",
    "Sensitive table read.": "Sensibler Tabellenzugriff.",
    "Export": "Export",
    "Large data movement.": "Große Datenbewegung.",
    "Escalation": "Eskalation",
    "Denied admin-level action.": "Verweigerte Admin-Aktion.",
    "Evidence trail": "Nachweiskette",
    "No evidence for investigation.": "Kein Nachweis für Untersuchung.",
    "The action happened, but audit logging is disabled, so no new event was recorded.": "Die Aktion wurde ausgeführt, aber Audit Logging ist deaktiviert; daher wurde kein neues Ereignis aufgezeichnet.",
    "Suspicious activity detected": "Verdächtige Aktivität erkannt",
    "Multiple failed or sensitive actions occurred. In a real system this should alert a responder.": "Mehrere fehlgeschlagene oder sensible Aktionen sind aufgetreten. In einem echten System sollte das einen Responder alarmieren.",
    "Time": "Zeit",
    "Actor": "Akteur",
    "Event": "Ereignis",
    "Object": "Objekt",
    "Signal": "Signal",
    "No audit events yet.": "Noch keine Audit-Ereignisse.",
    "unknown actor": "unbekannter Akteur",
    "large data movement": "große Datenbewegung",
    "privilege attempt": "Privilegienversuch",
    "Alert signal": "Alarmsignal",
    "Investigation evidence": "Untersuchungsnachweis",
    "Accountability": "Nachvollziehbarkeit",
    "Connect actions to users, services, and request paths.": "Verknüpfe Aktionen mit Nutzern, Services und Anfragepfaden.",
    "Incident response": "Incident Response",
    "Reconstruct what happened and which records may be affected.": "Rekonstruiere, was passiert ist und welche Datensätze betroffen sein könnten.",
    "Anomaly detection": "Anomalieerkennung",
    "Spot unusual failures, privileged actions, and large exports.": "Erkenne ungewöhnliche Fehler, privilegierte Aktionen und große Exporte.",
    "Compliance": "Compliance",
    "Show that sensitive data access is monitored and reviewable.": "Zeige, dass Zugriff auf sensible Daten überwacht und prüfbar ist.",
    "Audit logs support incident response and compliance when they include enough context.": "Audit-Logs unterstützen Incident Response und Compliance, wenn sie genug Kontext enthalten.",
    "Track actor, action, object, result, and signal so responders can reconstruct events.": "Erfasse Akteur, Aktion, Objekt, Ergebnis und Signal, damit Responder Ereignisse rekonstruieren können.",
    "Audit logs support incident response and compliance.": "Audit-Logs unterstützen Incident Response und Compliance.",
    "Log security-relevant database events centrally and protect logs from tampering.": "Protokolliere sicherheitsrelevante Datenbankereignisse zentral und schütze Logs vor Manipulation.",
    "Alerts need enough context to become evidence.": "Alerts brauchen genug Kontext, um zu Nachweisen zu werden.",
    "Database Security Playground - audit logging module.": "Database Security Playground - Audit-Logging-Modul.",

    "Database Network Exposure": "Database Network Exposure",
    "Send a packet and see whether it reaches the database or gets blocked.": "Sende ein Paket und sieh, ob es die Datenbank erreicht oder blockiert wird.",
    "Review required": "Prüfung erforderlich",
    "Security Controls": "Security Controls",
    "Current Controls": "Aktuelle Kontrollen",
    "Current security status": "Aktueller Sicherheitsstatus",
    "Public Database Port": "Öffentlicher Datenbank-Port",
    "Direct internet access": "Direkter Internetzugriff",
    "Protection": "Schutz",
    "Internal Network Only": "Nur internes Netzwerk",
    "Private service path": "Privater Service-Pfad",
    "Firewall Enabled": "Firewall aktiviert",
    "Policy enforcement": "Richtliniendurchsetzung",
    "TLS Enabled": "TLS aktiviert",
    "Encrypted transport": "Verschlüsselter Transport",
    "Simulation": "Simulation",
    "Access test": "Zugriffstest",
    "Source": "Quelle",
    "Packet source": "Paketquelle",
    "Internet": "Internet",
    "Untrusted origin": "Nicht vertrauenswürdige Herkunft",
    "Application": "Anwendung",
    "Approved service": "Freigegebener Service",
    "Privileged access": "Privilegierter Zugriff",
    "Packet action": "Paketaktion",
    "Read Data": "Daten lesen",
    "Data request": "Datenanfrage",
    "Export Data": "Daten exportieren",
    "Bulk transfer": "Massentransfer",
    "Connect": "Verbinden",
    "Open session": "Sitzung öffnen",
    "Test Access": "Zugriff testen",
    "Packet preview": "Paketvorschau",
    "Packet Preview": "Paketvorschau",
    "Request package": "Anfragepaket",
    "Expand packet": "Paket aufklappen",
    "Animated Result": "Animiertes Ergebnis",
    "Packet path": "Paketpfad",
    "Not tested": "Nicht getestet",
    "Waiting for test": "Wartet auf Test",
    "Explanation": "Erklärung",
    "Test access to see the decision.": "Teste den Zugriff, um die Entscheidung zu sehen.",
    "Network security path": "Netzwerk-Sicherheitspfad",
    "Selected source": "Ausgewählte Quelle",
    "Firewall": "Firewall",
    "Network control": "Netzwerkkontrolle",
    "Database": "Datenbank",
    "Waiting": "Wartet",
    "Blocked": "Blockiert",
    "Test access to see whether the request reaches the database.": "Teste den Zugriff, um zu sehen, ob die Anfrage die Datenbank erreicht.",
    "Choose a source and action, then test access.": "Wähle Quelle und Aktion, dann teste den Zugriff.",
    "A public database port exposes the service directly to attackers.": "Ein öffentlicher Datenbank-Port macht den Service direkt für Angreifer erreichbar.",
    "Network segmentation restricts access paths and reduces attack surface.": "Netzwerksegmentierung beschränkt Zugriffspfade und reduziert die Angriffsfläche.",
    "Firewalls enforce policy before traffic reaches the database.": "Firewalls erzwingen Richtlinien, bevor Traffic die Datenbank erreicht.",
    "No reachable database listener.": "Kein erreichbarer Datenbank-Listener.",
    "No route is available to the database.": "Es gibt keine Route zur Datenbank.",
    "No route": "Keine Route",
    "Database restricted to internal network.": "Datenbank auf internes Netzwerk beschränkt.",
    "Internet access is prevented through segmentation.": "Internetzugriff wird durch Segmentierung verhindert.",
    "Private network": "Privates Netzwerk",
    "Firewall policy denied this source.": "Die Firewall-Richtlinie hat diese Quelle abgelehnt.",
    "Access stopped before reaching the database.": "Zugriff wurde vor der Datenbank gestoppt.",
    "Policy denied": "Richtlinie abgelehnt",
    "TLS Disabled": "TLS deaktiviert",
    "The request reached the database without encrypted transport.": "Die Anfrage erreichte die Datenbank ohne verschlüsselten Transport.",
    "Traffic is allowed, but credentials and data are exposed on the network path.": "Traffic ist erlaubt, aber Zugangsdaten und Daten sind auf dem Netzwerkpfad sichtbar.",
    "Allowed, unencrypted": "Erlaubt, unverschlüsselt",
    "The request reached the database. Transport encryption was enabled.": "Die Anfrage erreichte die Datenbank. Transportverschlüsselung war aktiviert.",
    "Traffic is encrypted, but the service remains exposed.": "Traffic ist verschlüsselt, aber der Service bleibt exponiert.",
    "The request used an approved private path.": "Die Anfrage nutzte einen freigegebenen privaten Pfad.",
    "Allowed through": "Durchgelassen",
    "Allowed, insecure": "Erlaubt, unsicher",
    "Allowed": "Erlaubt",
    "Reached": "Erreicht",
    "Not reached": "Nicht erreicht",
    "Run Test Access to evaluate the updated path.": "Führe Zugriff testen aus, um den aktualisierten Pfad zu bewerten.",
    "The packet path will explain the control after you test access.": "Der Paketpfad erklärt die Kontrolle nach dem Zugriffstest.",
    "Request reached database": "Anfrage erreichte die Datenbank",
    "Blocked before reaching database": "Vor der Datenbank blockiert",
    "Public port exposed": "Öffentlicher Port exponiert",
    "Internal network only": "Nur internes Netzwerk",
    "Settings changed. Test access again to validate the path.": "Einstellungen geändert. Teste den Zugriff erneut, um den Pfad zu prüfen.",
    "Source changed. Test access again from the start.": "Quelle geändert. Teste den Zugriff erneut von Anfang an.",
    "Action changed. Test access again from the start.": "Aktion geändert. Teste den Zugriff erneut von Anfang an.",
    "Test access to see whether the selected request reaches the database.": "Teste den Zugriff, um zu sehen, ob die ausgewählte Anfrage die Datenbank erreicht.",
    "Database Security Playground - network exposure module.": "Database Security Playground - Network-Exposure-Modul.",

    "Secure Database Configuration": "Secure Database Configuration",
    "Assemble a PostgreSQL baseline and watch the risk score change as controls are added.": "Baue eine PostgreSQL-Baseline zusammen und beobachte, wie sich der Risikowert beim Hinzufügen von Kontrollen verändert.",
    "Open Postgres runtime": "Postgres-Laufzeit öffnen",
    "Optional details": "Optionale Details",
    "Configuration areas and Postgres runtime": "Konfigurationsbereiche und Postgres-Laufzeit",
    "Configuration areas": "Konfigurationsbereiche",
    "Choose the part of the configuration to inspect": "Wähle den Konfigurationsbereich zur Prüfung",
    "Use the Postgres runtime tab for the live Docker database status, TLS/container hardening notes, and risky-vs-hardened file comparison.": "Nutze den Postgres-Laufzeit-Tab für den Live-Status der Docker-Datenbank, Hinweise zu TLS/Container-Härtung und den Vergleich riskanter und gehärteter Dateien.",
    "Configuration area": "Konfigurationsbereich",
    "Baseline review": "Baseline-Prüfung",
    "Checklist and risk score": "Checkliste und Risikowert",
    "Postgres runtime": "Postgres-Laufzeit",
    "Live DB status and hardening": "Live-DB-Status und Härtung",
    "Build a secure PostgreSQL baseline": "Sichere PostgreSQL-Baseline bauen",
    "Use presets to compare risky and secure examples, or drag blocks into the target configuration.": "Nutze Vorlagen zum Vergleich riskanter und sicherer Beispiele oder ziehe Blöcke in die Zielkonfiguration.",
    "Load Insecure Example": "Unsicheres Beispiel laden",
    "Load Secure Example": "Sicheres Beispiel laden",
    "Review configuration": "Konfiguration prüfen",
    "Review again": "Erneut prüfen",
    "Risk score": "Risikowert",
    "Missing controls": "Fehlende Kontrollen",
    "Public network access": "Öffentlicher Netzwerkzugriff",
    "Root/default database user": "Root-/Standard-Datenbanknutzer",
    "Hardcoded credentials": "Hartcodierte Zugangsdaten",
    "Protected controls": "Geschützte Kontrollen",
    "PostgreSQL configuration builder": "PostgreSQL-Konfigurationsbuilder",
    "Assemble the deployment baseline": "Deployment-Baseline zusammenbauen",
    "Drag one PostgreSQL block into each control. Risk, missing controls, and generated config update immediately.": "Ziehe je einen PostgreSQL-Block in jede Kontrolle. Risiko, fehlende Kontrollen und generierte Konfiguration aktualisieren sich sofort.",
    "Required controls": "Erforderliche Kontrollen",
    "A secure database baseline is built from multiple controls.": "Eine sichere Datenbank-Baseline besteht aus mehreren Kontrollen.",
    "7 controls": "7 Kontrollen",
    "Drop identity block here": "Identity-Block hier ablegen",
    "Drop authentication block here": "Authentifizierungsblock hier ablegen",
    "Drop network block here": "Netzwerkblock hier ablegen",
    "Drop TLS block here": "TLS-Block hier ablegen",
    "Drop privileges block here": "Privileges-Block hier ablegen",
    "Drop audit block here": "Audit-Block hier ablegen",
    "Drop backup block here": "Backup-Block hier ablegen",
    "Available configuration blocks": "Verfügbare Konfigurationsblöcke",
    "Available PostgreSQL config blocks": "Verfügbare PostgreSQL-Konfigurationsblöcke",
    "Drag blocks": "Blöcke ziehen",
    "Default administrative identity": "Administrative Standardidentität",
    "Backend network only": "Nur Backend-Netzwerk",
    "TLS required": "TLS erforderlich",
    "Broad schema access": "Breiter Schemazugriff",
    "Inline credential": "Zugangsdaten im Klartext",
    "Traceable security events": "Nachvollziehbare Sicherheitsereignisse",
    "No restore point": "Kein Wiederherstellungspunkt",
    "Application-scoped identity": "Anwendungsbezogene Identität",
    "Plain host connection": "Unverschlüsselte Host-Verbindung",
    "Task-scoped grants": "Aufgabenbezogene Rechte",
    "Published database listener": "Veröffentlichter Datenbank-Listener",
    "Recoverable baseline": "Wiederherstellbare Baseline",
    "No security event trail": "Keine Security-Event-Spur",
    "Strong password authentication": "Starke Passwortauthentifizierung",
    "Generated PostgreSQL Config": "Generierte PostgreSQL-Konfiguration",
    "Live preview": "Live-Vorschau",
    "Live configuration findings": "Live-Konfigurationsbefunde",
    "Evidence from the review gate": "Nachweis aus dem Review-Gate",
    "See what is satisfied, blocked, or still risky after running the final review.": "Sieh, was nach der finalen Prüfung erfüllt, blockiert oder noch riskant ist.",
    "Review gate": "Review-Gate",
    "Review is still required before this module counts as complete.": "Eine Prüfung ist erforderlich, bevor dieses Modul als abgeschlossen zählt.",
    "Dedicated DB user": "Dedizierter DB-Nutzer",
    "Replace root/default login with an application identity.": "Ersetze Root-/Standard-Login durch eine Anwendungsidentität.",
    "Least privilege grants": "Least-Privilege-Rechte",
    "Limit the app user to required schemas and operations.": "Beschränke den App-Nutzer auf benötigte Schemas und Operationen.",
    "No public DB port": "Kein öffentlicher DB-Port",
    "Bind the listener to a private network path only.": "Binde den Listener nur an einen privaten Netzwerkpfad.",
    "TLS enabled": "TLS aktiviert",
    "Require encrypted database connections.": "Erzwinge verschlüsselte Datenbankverbindungen.",
    "Audit logging enabled": "Audit Logging aktiviert",
    "Record authentication, access, export, and privilege events.": "Zeichne Authentifizierung, Zugriff, Export und Privilegienereignisse auf.",
    "Backups configured": "Backups konfiguriert",
    "Enable scheduled backups and restore testing.": "Aktiviere geplante Backups und Restore-Tests.",
    "Secrets not hardcoded": "Secrets nicht hartcodiert",
    "Move credentials to environment or a secret manager.": "Verschiebe Zugangsdaten in die Umgebung oder einen Secret Manager.",
    "Release baseline": "Release-Baseline",
    "Config blocks": "Konfigurationsblöcke",
    "Identity, grants, network, TLS": "Identity, Rechte, Netzwerk, TLS",
    "Generated config": "Generierte Konfiguration",
    "Preview updates while building": "Vorschau aktualisiert sich beim Bauen",
    "Ship or block decision": "Freigabe- oder Blockierentscheidung",
    "Risk appears on review": "Risiko erscheint bei der Prüfung",
    "Hardened baseline can complete": "Gehärtete Baseline kann abschließen",
    "Before review": "Vor der Prüfung",
    "Assemble the config from blocks and read the generated preview.": "Baue die Konfiguration aus Blöcken zusammen und lies die generierte Vorschau.",
    "After review": "Nach der Prüfung",
    "The review turns the current choices into release blockers or approved controls.": "Die Prüfung wandelt die aktuellen Entscheidungen in Release-Blocker oder freigegebene Kontrollen.",
    "Secure defaults prevent hardening from becoming optional cleanup.": "Sichere Defaults verhindern, dass Härtung zur optionalen Nacharbeit wird.",
    "Block release on critical configuration gaps.": "Blockiere Releases bei kritischen Konfigurationslücken.",
    "Make the secure database configuration the normal configuration.": "Mache die sichere Datenbankkonfiguration zur normalen Konfiguration.",
    "Root users, broad grants, hardcoded secrets, and public database ports should remain deployment blockers.": "Root-Nutzer, breite Rechte, hartcodierte Secrets und öffentliche Datenbank-Ports sollten Deployment-Blocker bleiben.",
    "Connected database mode": "Verbundener Datenbankmodus",
    "Checking database": "Datenbank wird geprüft",
    "Back to builder": "Zurück zum Builder",
    "Waiting for health check": "Wartet auf Health Check",
    "Checking the active demo database.": "Aktive Demo-Datenbank wird geprüft.",
    "Demo container": "Demo-Container",
    "The Compose setup provides Postgres and the configuration examples shown below.": "Das Compose-Setup stellt Postgres und die unten gezeigten Konfigurationsbeispiele bereit.",
    "Postgres hardening": "Postgres-Härtung",
    "What is enabled in the demo container": "Was im Demo-Container aktiviert ist",
    "Private DB network": "Privates DB-Netzwerk",
    "Postgres is only exposed to Docker's internal backend network; port 5432 is not published to the host.": "Postgres ist nur im internen Docker-Backend-Netzwerk erreichbar; Port 5432 wird nicht auf dem Host veröffentlicht.",
    "TLS-only TCP": "Nur TLS-TCP",
    "Secrets outside Compose": "Secrets außerhalb von Compose",
    "App and admin passwords are loaded from Docker secret files instead of being hardcoded in Compose.": "App- und Admin-Passwörter werden aus Docker-Secret-Dateien geladen, statt in Compose hartcodiert zu sein.",
    "Least privilege role": "Least-Privilege-Rolle",
    "The application connects as": "Die Anwendung verbindet sich als",
    "with scoped grants, not as the Postgres admin role.": "mit begrenzten Rechten, nicht als Postgres-Admin-Rolle.",
    "Container restrictions": "Container-Einschränkungen",
    "Compose applies read-only filesystems, tmpfs runtime paths, dropped capabilities,": "Compose nutzt schreibgeschützte Dateisysteme, tmpfs-Laufzeitpfade, entfernte Capabilities,",
    "and process limits.": "und Prozesslimits.",
    "Demo caveat": "Demo-Hinweis",
    "Self-signed certificate": "Selbstsigniertes Zertifikat",
    "TLS encryption is enforced, but certificate trust is relaxed for this local demo. Production should verify a trusted CA.": "TLS-Verschlüsselung wird erzwungen, aber das Zertifikatsvertrauen ist für diese lokale Demo gelockert. Produktion sollte eine vertrauenswürdige CA prüfen.",
    "Why this matters": "Warum das wichtig ist",
    "Use the file tabs to compare how networking, TLS, grants, and secrets differ between risky and hardened setups.": "Nutze die Datei-Tabs, um Unterschiede bei Netzwerk, TLS, Rechten und Secrets zwischen riskanten und gehärteten Setups zu vergleichen.",
    "Database Security Playground - secure configuration module.": "Database Security Playground - Secure-Configuration-Modul.",
    "Application connects as root/default user.": "Die Anwendung verbindet sich als Root-/Standardnutzer.",
    "Application connects as a dedicated app_user.": "Die Anwendung verbindet sich als dedizierter app_user.",
    "A leaked app credential can become full database control.": "Ein offengelegter App-Zugang kann zur vollständigen Kontrolle über die Datenbank führen.",
    "App account has ALL PRIVILEGES.": "Das App-Konto hat ALL PRIVILEGES.",
    "Public privileges are revoked and app grants are task-scoped.": "Öffentliche Rechte sind entzogen und App-Rechte sind auf Aufgaben beschränkt.",
    "Broad grants increase damage from SQLi or credential theft.": "Breite Rechte erhöhen den Schaden durch SQLi oder gestohlene Zugangsdaten.",
    "Database listener is reachable on a public port.": "Der Datenbank-Listener ist über einen öffentlichen Port erreichbar.",
    "Database listener is internal-only.": "Der Datenbank-Listener ist nur intern erreichbar.",
    "Internet exposure turns weak credentials or old services into direct attack paths.": "Internet-Exposition macht schwache Zugangsdaten oder alte Services zu direkten Angriffspfaden.",
    "TLS is not required for DB traffic.": "TLS ist für DB-Traffic nicht erforderlich.",
    "TLS is required for DB traffic.": "TLS ist für DB-Traffic erforderlich.",
    "Credentials and queries may be exposed on the network path.": "Zugangsdaten und Abfragen können auf dem Netzwerkpfad sichtbar werden.",
    "Security-relevant DB events are not logged.": "Sicherheitsrelevante DB-Ereignisse werden nicht protokolliert.",
    "Authentication, access, export, and privilege events are logged.": "Authentifizierung, Zugriff, Export und Privilegienereignisse werden protokolliert.",
    "Incidents become harder to investigate and prove.": "Vorfälle werden schwerer zu untersuchen und zu belegen.",
    "No scheduled, restore-tested backup exists.": "Es gibt kein geplantes, restore-getestetes Backup.",
    "Backups are scheduled and restore-tested.": "Backups sind geplant und restore-getestet.",
    "Recovery from deletion, ransomware, or operator error is uncertain.": "Wiederherstellung nach Löschung, Ransomware oder Bedienfehler ist unsicher.",
    "Password handling is weak or hardcoded.": "Passworthandling ist schwach oder hartcodiert.",
    "SCRAM password authentication is required.": "SCRAM-Passwortauthentifizierung ist erforderlich.",
    "Weak authentication increases the blast radius of leaked credentials.": "Schwache Authentifizierung vergrößert den Schaden durch offengelegte Zugangsdaten.",
    "Local socket": "Lokaler Socket",
    "Allowed locally": "Lokal erlaubt",
    "trust accepts local socket connections without a password check. This is convenient for bootstrap, but should be scoped carefully.": "trust akzeptiert lokale Socket-Verbindungen ohne Passwortprüfung. Das ist praktisch für Bootstrap, sollte aber sorgfältig begrenzt werden.",
    "The demo keeps local socket trust for container-local bootstrap. Production teams often tighten this further.": "Die Demo behält lokalen Socket-Trust für containerlokales Bootstrap bei. Produktionsteams schränken das oft weiter ein.",
    "Host without TLS": "Host ohne TLS",
    "Allowed with weak protection": "Mit schwachem Schutz erlaubt",
    "The risky policy accepts host connections with md5 password authentication and no TLS requirement.": "Die riskante Richtlinie akzeptiert Host-Verbindungen mit md5-Passwortauthentifizierung und ohne TLS-Pflicht.",
    "Rejected": "Abgelehnt",
    "The hardened policy rejects hostnossl before authentication, so plaintext database traffic cannot proceed.": "Die gehärtete Richtlinie lehnt hostnossl vor der Authentifizierung ab, sodass Klartext-Datenbanktraffic nicht fortgesetzt wird.",
    "Host with TLS": "Host mit TLS",
    "Allowed, but not enforced": "Erlaubt, aber nicht erzwungen",
    "The risky policy may allow host traffic, but it does not require the encrypted hostssl path.": "Die riskante Richtlinie kann Host-Traffic erlauben, erzwingt aber nicht den verschlüsselten hostssl-Pfad.",
    "Allowed with SCRAM": "Mit SCRAM erlaubt",
    "The hardened policy allows TLS host connections and requires SCRAM password authentication.": "Die gehärtete Richtlinie erlaubt TLS-Host-Verbindungen und verlangt SCRAM-Passwortauthentifizierung.",
    "Choose a block from the palette": "Wähle einen Block aus der Palette",
    "Drop blocks into Target config to generate a baseline.": "Lege Blöcke in der Zielkonfiguration ab, um eine Baseline zu erzeugen.",
    "Missing slots": "Fehlende Slots",
    "slots filled": "Slots gefüllt",
    "Hardened config complete": "Gehärtete Konfiguration vollständig",
    "hardened decisions": "gehärtete Entscheidungen",
    "Risky policy": "Riskante Richtlinie",
    "Hardened policy": "Gehärtete Richtlinie",
    "No block selected for this area yet.": "Für diesen Bereich ist noch kein Block ausgewählt.",
    "Drag a matching block into Target config.": "Ziehe einen passenden Block in die Zielkonfiguration.",
    "Configuration blocked": "Konfiguration blockiert",
    "Security review required": "Security Review erforderlich",
    "Critical blockers are gone, but resilience or visibility gaps remain.": "Kritische Blocker sind entfernt, aber Resilienz- oder Sichtbarkeitslücken bleiben.",
    "Baseline approved for demo": "Baseline für Demo freigegeben",
    "Critical blockers are removed and operational controls are in place.": "Kritische Blocker sind entfernt und operative Kontrollen sind vorhanden.",
    "Several risky defaults remain. This may be acceptable for a toy demo, not for production.": "Mehrere riskante Defaults bleiben bestehen. Für eine Spiel-Demo mag das akzeptabel sein, für Produktion nicht.",
    "Start by dragging blocks into Target config. Findings stay neutral until an area has a selected block.": "Starte, indem du Blöcke in die Zielkonfiguration ziehst. Befunde bleiben neutral, bis ein Bereich einen ausgewählten Block hat.",
    "The critical blockers are handled, but resilience or visibility controls are still missing.": "Die kritischen Blocker sind behoben, aber Resilienz- oder Sichtbarkeitskontrollen fehlen noch.",
    "No critical blockers": "Keine kritischen Blocker",
    "Needs baseline": "Baseline nötig",
    "Waiting for blocks": "Wartet auf Blöcke",
    "Drop one option per config area, then run the review.": "Lege pro Konfigurationsbereich eine Option ab und starte dann die Prüfung.",
    "No config selected yet": "Noch keine Konfiguration ausgewählt",
    "The builder starts empty so the learner has to assemble the baseline before it is judged.": "Der Builder startet leer, damit Lernende die Baseline vor der Bewertung selbst zusammenbauen.",
    "Risk floor active": "Risikountergrenze aktiv",
    "Root/default user, public DB port, broad privileges, and hardcoded secrets are removed in the current preview.": "Root-/Standardnutzer, öffentlicher DB-Port, breite Rechte und hartcodierte Secrets sind in der aktuellen Vorschau entfernt.",
    "Postgres connected": "Postgres verbunden",
    "SQLite local mode": "Lokaler SQLite-Modus",
    "Postgres runtime is active": "Postgres-Laufzeit ist aktiv",
    "The demo is connected to the Postgres container. Use the sections below to inspect the related hardening configuration.": "Die Demo ist mit dem Postgres-Container verbunden. Nutze die Bereiche unten, um die zugehörige Härtungskonfiguration zu prüfen.",
    "SQLite local runtime is active": "Lokale SQLite-Laufzeit ist aktiv",
    "Start with Docker Compose to view the Postgres container runtime.": "Starte mit Docker Compose, um die Postgres-Container-Laufzeit zu sehen.",
    "Health check failed": "Health Check fehlgeschlagen",
    "Could not check database": "Datenbank konnte nicht geprüft werden",
    "Connection policy": "Verbindungsrichtlinie",
    "Each row is evaluated as an access rule. The hardened policy explicitly rejects non-TLS host connections and only allows TLS connections with SCRAM authentication.": "Jede Zeile wird als Zugriffsregel bewertet. Die gehärtete Richtlinie lehnt Nicht-TLS-Host-Verbindungen explizit ab und erlaubt nur TLS-Verbindungen mit SCRAM-Authentifizierung.",
    "The left side shows the shortcut that creates risk; the right side shows the hardened reference used by this demo.": "Links steht die Abkürzung, die Risiko erzeugt; rechts steht die gehärtete Referenz dieser Demo.",
    "Connection": "Verbindung",
    "User": "Nutzer",
    "Decision / Auth": "Entscheidung / Auth",
    "Could not load config examples": "Konfigurationsbeispiele konnten nicht geladen werden",

    "Prepared Statements": "Prepared Statements",
    "Prepared Statements enabled: user input can no longer manipulate SQL query structure.": "Prepared Statements aktiviert: Benutzereingaben können die SQL-Abfragestruktur nicht mehr manipulieren.",
    "Prepared Statements disabled: user input can change SQL query structure in vulnerable paths.": "Prepared Statements deaktiviert: Benutzereingaben können in verwundbaren Pfaden die SQL-Abfragestruktur verändern.",
    "SQL input can still alter query logic.": "SQL-Eingaben können weiterhin Query-Logik verändern.",
    "RBAC and Masking": "RBAC und Masking",
    "RBAC and masking enabled: records and sensitive fields are restricted by role.": "RBAC und Masking aktiviert: Datensätze und sensible Felder werden nach Rolle eingeschränkt.",
    "RBAC or masking disabled: roles can see more data than the task requires.": "RBAC oder Masking deaktiviert: Rollen können mehr Daten sehen, als die Aufgabe erfordert.",
    "Role boundaries or sensitive-field reduction are incomplete.": "Rollengrenzen oder Reduktion sensibler Felder sind unvollständig.",
    "Output Encoding": "Output Encoding",
    "Output Encoding enabled: untrusted content renders as text.": "Output Encoding aktiviert: Nicht vertrauenswürdige Inhalte werden als Text gerendert.",
    "Output Encoding disabled: untrusted content can become active page markup.": "Output Encoding deaktiviert: Nicht vertrauenswürdige Inhalte können aktives Seiten-Markup werden.",
    "Untrusted content can become active markup.": "Nicht vertrauenswürdige Inhalte können aktives Markup werden.",
    "Audit Logging enabled: security-relevant actions are now traceable.": "Audit Logging aktiviert: Sicherheitsrelevante Aktionen sind jetzt nachvollziehbar.",
    "Audit Logging disabled: security-relevant actions can occur without useful evidence.": "Audit Logging deaktiviert: Sicherheitsrelevante Aktionen können ohne brauchbare Nachweise stattfinden.",
    "Security events have limited investigation evidence.": "Sicherheitsereignisse haben nur begrenzte Untersuchungsnachweise.",
    "Network Segmentation": "Netzwerksegmentierung",
    "Network Security": "Netzwerksicherheit",
    "Network Segmentation enabled: the database is no longer directly reachable from the Internet.": "Netzwerksegmentierung aktiviert: Die Datenbank ist nicht mehr direkt aus dem Internet erreichbar.",
    "Network Segmentation disabled: direct database exposure becomes the dominant risk.": "Netzwerksegmentierung deaktiviert: Direkte Datenbankexposition wird zum dominierenden Risiko.",
    "Database access can bypass the intended application path.": "Datenbankzugriff kann den vorgesehenen Anwendungspfad umgehen.",
    "Secure Configuration enabled: least privilege, secrets handling, TLS, and hardening are in scope.": "Secure Configuration aktiviert: Least Privilege, Secret-Handling, TLS und Härtung sind abgedeckt.",
    "Secure Configuration disabled: risky defaults can undermine otherwise good controls.": "Secure Configuration deaktiviert: Riskante Defaults können sonst gute Kontrollen untergraben.",
    "Risky defaults, broad grants, weak secrets, or missing TLS can remain.": "Riskante Defaults, breite Rechte, schwache Secrets oder fehlendes TLS können bestehen bleiben.",
    "Data Protection": "Datenschutz",
    "Monitoring": "Monitoring",
    "Authentication": "Authentifizierung",

    "Try the bypass payload, then switch to Protected.": "Probiere den Bypass-Payload und wechsle dann zu Geschützt.",
    "Enable protected mode and continue": "Geschützten Modus aktivieren und fortfahren",
    "Run a login check in Vulnerable mode before completing this step.": "Führe zuerst eine Login-Prüfung im verwundbaren Modus aus.",
    "Continue to XSS": "Weiter zu XSS",
    "Post a payload, then switch to Protected.": "Poste einen Payload und wechsle dann zu Geschützt.",
    "Enable protected output and continue": "Geschützte Ausgabe aktivieren und fortfahren",
    "Post a comment in Vulnerable mode before completing this step.": "Poste zuerst einen Kommentar im verwundbaren Modus.",
    "Continue to Data Masking": "Weiter zu Data Masking",
    "See the exposed data first, then enable RBAC and masking.": "Sieh zuerst die offengelegten Daten und aktiviere dann RBAC und Masking.",
    "Continue with RBAC + masking enabled": "Mit aktiviertem RBAC + Masking fortfahren",
    "Select a role, review the exposed data, then enable protection to compare the result.": "Wähle eine Rolle, prüfe die offengelegten Daten und aktiviere dann den Schutz für den Vergleich.",
    "Continue to Audit": "Weiter zu Audit",
    "Trigger an event and inspect the evidence trail.": "Löse ein Ereignis aus und prüfe die Nachweiskette.",
    "Continue to Network": "Weiter zu Network",
    "Trigger at least one audit-relevant event before continuing.": "Löse mindestens ein auditrelevantes Ereignis aus, bevor du fortfährst.",
    "Test access while exposed, then make the DB private.": "Teste den Zugriff im exponierten Zustand und mache die DB dann privat.",
    "Continue to Config": "Weiter zu Config",
    "Test internet access while the database is exposed, then make the network segmented before continuing.": "Teste Internetzugriff, während die Datenbank exponiert ist, und segmentiere dann das Netzwerk.",
    "Assemble the PostgreSQL baseline, then review the result.": "Baue die PostgreSQL-Baseline zusammen und prüfe dann das Ergebnis.",
    "Place configuration blocks and review the generated PostgreSQL baseline before finishing.": "Platziere Konfigurationsblöcke und prüfe die generierte PostgreSQL-Baseline vor dem Abschluss.",
    "Finish on Overview": "In der Übersicht abschließen",
    "Try the login bypass in Vulnerable mode, then switch to Protected mode.": "Probiere den Login-Bypass im verwundbaren Modus und wechsle dann zu Geschützt.",
    "Prepared statements keep user input as data instead of SQL logic.": "Prepared Statements halten Benutzereingaben als Daten statt als SQL-Logik.",
    "The same payload no longer changes the query and the login fails safely.": "Derselbe Payload verändert die Abfrage nicht mehr und der Login schlägt sicher fehl.",
    "Run the login check first; the result unlocks the protected comparison.": "Führe zuerst die Login-Prüfung aus; das Ergebnis öffnet den geschützten Vergleich.",
    "Post a demo comment in Vulnerable mode, then render it in Protected mode.": "Poste einen Demo-Kommentar im verwundbaren Modus und rendere ihn dann geschützt.",
    "Safe output APIs keep untrusted markup from becoming active page structure.": "Sichere Ausgabe-APIs verhindern, dass nicht vertrauenswürdiges Markup aktive Seitenstruktur wird.",
    "The payload appears as visible text instead of a link, download, or HTML node.": "Der Payload erscheint als sichtbarer Text statt als Link, Download oder HTML-Knoten.",
    "Post one payload, then switch to Protected output.": "Poste einen Payload und wechsle dann zur geschützten Ausgabe.",
    "Select a role and review which customer fields it can see.": "Wähle eine Rolle und prüfe, welche Kundenfelder sie sehen kann.",
    "Authorization and masking solve different data exposure problems.": "Autorisierung und Masking lösen unterschiedliche Offenlegungsprobleme.",
    "RBAC and masking are enabled, and the selected role only receives appropriate fields.": "RBAC und Masking sind aktiviert, und die ausgewählte Rolle erhält nur passende Felder.",
    "Review a role, then leave RBAC and masking enabled.": "Prüfe eine Rolle und lasse RBAC und Masking aktiviert.",
    "Trigger a database-relevant event and inspect the evidence trail.": "Löse ein datenbankrelevantes Ereignis aus und prüfe die Nachweiskette.",
    "Audit logs turn suspicious activity into investigation evidence.": "Audit-Logs machen verdächtige Aktivität zu Untersuchungsnachweisen.",
    "The event appears with actor, action, object, result, and signal context.": "Das Ereignis erscheint mit Akteur, Aktion, Objekt, Ergebnis und Signal-Kontext.",
    "Trigger an event, then continue when evidence is visible.": "Löse ein Ereignis aus und fahre fort, wenn der Nachweis sichtbar ist.",
    "Choose a source and action, test access, then restrict direct database access.": "Wähle Quelle und Aktion, teste den Zugriff und beschränke dann direkten Datenbankzugriff.",
    "Network segmentation keeps users on the intended app and API path.": "Netzwerksegmentierung hält Nutzer auf dem vorgesehenen App- und API-Pfad.",
    "Direct internet traffic is blocked while the expected API path remains available.": "Direkter Internettraffic wird blockiert, während der erwartete API-Pfad verfügbar bleibt.",
    "Run one exposed access test, then make the database private.": "Führe einen exponierten Zugriffstest aus und mache die Datenbank dann privat.",
    "Assemble PostgreSQL controls into the target configuration, then review the generated baseline.": "Baue PostgreSQL-Kontrollen in die Zielkonfiguration ein und prüfe die generierte Baseline.",
    "Secure defaults stop risky database settings from becoming optional cleanup.": "Sichere Defaults verhindern, dass riskante Datenbankeinstellungen optionale Nacharbeit werden.",
    "The review approves the baseline after critical blockers are removed.": "Die Prüfung gibt die Baseline frei, sobald kritische Blocker entfernt sind.",
    "Use the builder or the secure preset, then review the configuration.": "Nutze den Builder oder die sichere Vorlage und prüfe dann die Konfiguration.",
    "Try the bypass payload first. Then enable protection and compare the result.": "Probiere zuerst den Bypass-Payload. Aktiviere dann den Schutz und vergleiche das Ergebnis.",
    "In Protected mode the payload stays data, not SQL logic.": "Im geschützten Modus bleibt der Payload Daten und wird nicht zu SQL-Logik.",
    "Post a payload and see how the browser renders it. Then switch to Protected.": "Poste einen Payload und beobachte das Browser-Rendering. Wechsle dann zu Geschützt.",
    "Protected mode shows the same input as text instead of active HTML.": "Der geschützte Modus zeigt dieselbe Eingabe als Text statt als aktives HTML.",
    "Start with the exposed records. Then enable RBAC and masking to compare the same role.": "Starte mit den offengelegten Datensätzen. Aktiviere dann RBAC und Masking, um dieselbe Rolle zu vergleichen.",
    "RBAC decides access. Masking reduces sensitive values.": "RBAC entscheidet über Zugriff. Masking reduziert sensible Werte.",
    "Trigger an event and check whether evidence is generated.": "Löse ein Ereignis aus und prüfe, ob Nachweise entstehen.",
    "The trail should show actor, action, object, result, and signal.": "Die Spur sollte Akteur, Aktion, Objekt, Ergebnis und Signal zeigen.",
    "Choose Internet, then test access. Make the database private and compare the result.": "Wähle Internet und teste den Zugriff. Mache die Datenbank privat und vergleiche das Ergebnis.",
    "The result should change from Allowed to Blocked for direct internet access.": "Das Ergebnis sollte für direkten Internetzugriff von Erlaubt zu Blockiert wechseln.",
    "Place blocks into the builder and watch the generated PostgreSQL config change.": "Platziere Blöcke im Builder und beobachte die generierte PostgreSQL-Konfiguration.",
    "On touch screens you can tap a block to add it to the matching control.": "Auf Touchscreens kannst du einen Block antippen, um ihn der passenden Kontrolle hinzuzufügen.",
    "This is the runtime reference. Go back to the baseline when you want to finish the demo.": "Dies ist die Laufzeitreferenz. Gehe zur Baseline zurück, wenn du die Demo abschließen möchtest.",
    "Start with exposed data, then compare the protected result.": "Starte mit offengelegten Daten und vergleiche dann das geschützte Ergebnis.",
    "Build the PostgreSQL baseline and watch the risk change.": "Baue die PostgreSQL-Baseline und beobachte die Risikoänderung.",
    "This step demonstrates how a concrete control changes the security outcome.": "Dieser Schritt zeigt, wie eine konkrete Kontrolle das Sicherheitsergebnis verändert.",
    "The result is visible and the required control is enabled.": "Das Ergebnis ist sichtbar und die erforderliche Kontrolle ist aktiviert.",
    "Complete the action in the module.": "Schließe die Aktion im Modul ab.",

    "Current": "Aktuell",
    "Done": "Erledigt",
    "Back to start": "Zurück zum Start",
    "Insecure active": "Unsicher aktiv",
    "Try bypass, then protect.": "Bypass testen, dann schützen.",
    "Post payload, then protect.": "Payload posten, dann schützen.",
    "Compare raw and protected data.": "Rohdaten und geschützte Daten vergleichen.",
    "Trigger event, inspect evidence.": "Ereignis auslösen, Nachweis prüfen.",
    "Send traffic, then make DB private.": "Traffic senden, dann DB privat machen.",
    "Apply secure baseline.": "Sichere Baseline anwenden.",
    "All six learning steps are complete.": "Alle sechs Lernschritte sind abgeschlossen.",
    "Review Start Screen": "Startansicht prüfen",
    "Try the bypass, then protect it.": "Teste den Bypass und schütze ihn dann.",
    "Inject markup, then encode output.": "Markup einschleusen, dann Ausgabe encodieren.",
    "Compare roles and exposed fields.": "Rollen und offengelegte Felder vergleichen.",
    "Trigger one event and inspect evidence.": "Ein Ereignis auslösen und Nachweise prüfen.",
    "Flow complete": "Ablauf abgeschlossen",
    "Use the overview as the closing summary.": "Nutze die Übersicht als Abschlusszusammenfassung.",
    "Then open Step 1.": "Dann Schritt 1 öffnen.",
    "Start guided lab": "Geführtes Lab starten",
    "Begin Step 1: SQL Injection": "Schritt 1 beginnen: SQL Injection",
    "Start insecure, then test the first bypass.": "Starte unsicher und teste dann den ersten Bypass.",
    "The unsafe result makes the prepared-statement fix easier to understand.": "Das unsichere Ergebnis macht den Prepared-Statement-Fix leichter verständlich.",
    "Post one payload before switching modes.": "Poste einen Payload, bevor du den Modus wechselst.",
    "Look for the same input changing from active markup to safe text.": "Achte darauf, wie dieselbe Eingabe von aktivem Markup zu sicherem Text wird.",
    "Compare one role before enabling the controls.": "Vergleiche eine Rolle, bevor du die Kontrollen aktivierst.",
    "RBAC limits records. Masking limits exposed fields.": "RBAC begrenzt Datensätze. Masking begrenzt offengelegte Felder.",
    "Trigger one event and inspect the trail.": "Löse ein Ereignis aus und prüfe die Spur.",
    "Useful evidence answers who, what, where, result, and signal.": "Nützliche Nachweise beantworten wer, was, wo, Ergebnis und Signal.",
    "Send a public packet before segmenting.": "Sende ein öffentliches Paket, bevor du segmentierst.",
    "Success means direct database access is blocked while the intended path stays available.": "Erfolg bedeutet: Direkter Datenbankzugriff ist blockiert, während der vorgesehene Pfad verfügbar bleibt.",
    "Review the insecure settings, then apply the secure baseline.": "Prüfe die unsicheren Einstellungen und wende dann die sichere Baseline an.",
    "The score improves when blockers are removed.": "Der Score verbessert sich, wenn Blocker entfernt werden.",
    "Lab complete. Use the start screen as the summary.": "Lab abgeschlossen. Nutze die Startansicht als Zusammenfassung.",
    "The completed lab is ready to present.": "Das abgeschlossene Lab ist bereit für die Präsentation.",
    "Use the insecure baseline to show the impact first, then apply each control and let the result change after the action.": "Nutze die unsichere Baseline, um zuerst die Auswirkung zu zeigen. Aktiviere dann jede Kontrolle und lasse das Ergebnis nach der Aktion wechseln.",
    "What changed?": "Was hat sich geändert?",
    "Controls are enabled for the current demo state.": "Kontrollen sind für den aktuellen Demo-Zustand aktiviert.",
    "Risk details": "Risikodetails",
    "Baseline controls": "Baseline-Kontrollen",
    "SQL values stay data.": "SQL-Werte bleiben Daten.",
    "Restrict records by role.": "Datensätze nach Rolle einschränken.",
    "Render markup as text.": "Markup als Text rendern.",
    "Keep evidence visible.": "Nachweise sichtbar halten.",
    "Remove direct DB path.": "Direkten DB-Pfad entfernen.",
    "Use hardened defaults.": "Gehärtete Defaults nutzen.",
    "No missing controls": "Keine fehlenden Kontrollen",
    "Score 8 is residual demo risk.": "Score 8 ist verbleibendes Demo-Risiko.",
    "missing controls": "fehlende Kontrollen",
    "Main drivers": "Haupttreiber",
    "Risk floor applied": "Risikountergrenze angewendet",
    "Critical missing controls prevent the score from appearing artificially low.": "Kritisch fehlende Kontrollen verhindern, dass der Score künstlich niedrig wirkt.",
    "Insecure baseline is active. Step 1 starts in SQL Injection.": "Unsichere Baseline ist aktiv. Schritt 1 startet in SQL Injection.",
    "The login builds one SQL string with user-controlled text. Payloads such as": "Der Login baut einen SQL-String mit benutzergesteuertem Text. Payloads wie",
    "can comment out the password check in vulnerable string-built SQL. The same class of bug can appear in any language when values are concatenated into SQL.": "können die Passwortprüfung in verwundbar zusammengesetztem SQL auskommentieren. Dieselbe Fehlerklasse kann in jeder Sprache auftreten, wenn Werte in SQL konkateniert werden.",
    "The login keeps SQL structure fixed with placeholders. The same payload is handled as a literal username, so it does not alter the query and the login fails.": "Der Login hält die SQL-Struktur mit Platzhaltern fest. Derselbe Payload wird als wörtlicher Benutzername behandelt, verändert die Abfrage nicht und der Login schlägt fehl.",
    "Clear comments": "Kommentare löschen",
    ", the browser parses tags as page structure. Links and downloads become active UI.": ", parst der Browser Tags als Seitenstruktur. Links und Downloads werden aktive UI.",
    ", angle brackets remain characters, not HTML.": ", bleiben spitze Klammern Zeichen und werden nicht zu HTML.",
    "Vulnerable mode: sensitive customer information is fully exposed for this role.": "Verwundbarer Modus: Sensible Kundendaten sind für diese Rolle vollständig sichtbar.",
    "Protected mode: RBAC and masking changed what this role can see. Compare the before and after views.": "Geschützter Modus: RBAC und Masking haben geändert, was diese Rolle sehen kann. Vergleiche Vorher und Nachher.",
    "RBAC disabled: role boundary removed": "RBAC deaktiviert: Rollengrenze entfernt",
    "Clear log": "Log löschen",
    "Audit logging on: security-relevant actions produce evidence.": "Audit Logging an: Sicherheitsrelevante Aktionen erzeugen Nachweise.",
    "Audit logging off: actions happen without an investigation trail.": "Audit Logging aus: Aktionen passieren ohne Untersuchungsspur.",
    "Security Controls": "Sicherheitskontrollen",
    "Control": "Kontrolle",
    "Drop network exposure block here": "Network-Exposure-Block hier ablegen",
    "Drop transport security block here": "Transport-Security-Block hier ablegen",
    "Drop audit logging block here": "Audit-Logging-Block hier ablegen",
    "Drop backup / recovery block here": "Backup-/Recovery-Block hier ablegen",
    "hardcoded credentials": "hartcodierte Zugangsdaten",
    "root/default database user": "Root-/Standard-Datenbanknutzer",
    "public database port": "öffentlicher Datenbank-Port",
    "broad privileges": "breite Rechte",
    "Run the login check, then enable Protected mode.": "Führe die Login-Prüfung aus und aktiviere dann Geschützt.",
    "Post the payload, then compare Protected output.": "Poste den Payload und vergleiche dann die geschützte Ausgabe.",
    "Select a role and compare protected data.": "Wähle eine Rolle und vergleiche geschützte Daten.",
    "Choose Internet, then test access.": "Wähle Internet und teste dann den Zugriff.",
    "Assemble and review the secure baseline.": "Baue und prüfe die sichere Baseline.",
    "Do this next": "Das als Nächstes tun",
    "Security Owl": "Security Owl",
    "Config": "Config",
    "Security Demo Walkthrough": "Security-Demo-Durchlauf",
    "Identity": "Identität",
    "Transport Security": "Transportsicherheit",
    "Privileges": "Rechte",
    "Backup / Recovery": "Backup / Wiederherstellung"
  };

  const dictionaries = { de };
  const originalText = new WeakMap();
  const originalAttributes = new WeakMap();
  let originalTitle = document.title;
  let applying = false;
  let pending = false;

  const skipSelector = [
    "script",
    "style",
    "noscript",
    "template",
    "code",
    "pre",
    "textarea",
    "input",
    "select",
    "option",
    ".query-box",
    ".config-file-preview",
    ".builder-code",
    ".packet-payload-preview",
    ".packet-payload-full",
    ".policy-preview",
    ".json-key",
    ".json-string",
    ".json-bool",
    ".json-number",
    ".packet-icon",
    ".brand-mark",
    "[data-no-i18n]",
    "[data-builder-option] strong"
  ].join(",");

  const translatableAttributes = ["aria-label", "title", "placeholder", "value"];

  function normalize(value) {
    return String(value || "").replace(/\s+/g, " ").trim();
  }

  function readLanguage() {
    const saved = localStorage.getItem(storageKey);
    return supportedLanguages.includes(saved) ? saved : fallbackLanguage;
  }

  function dynamicTranslate(source, lang) {
    if (lang !== "de") return source;
    const lookup = (value) => dictionaries.de[value] || value;
    const stepContext = source.match(/^Step (\d+) of 6 · (.+)$/);
    if (stepContext) return `Schritt ${stepContext[1]} von 6 · ${dynamicTranslate(stepContext[2], lang)}`;

    const riskScore = source.match(/^Risk score: (\d+)\/100 \((.+)\)\. (\d+)\/6 controls are currently enabled\.$/);
    if (riskScore) {
      return `Risikowert: ${riskScore[1]}/100 (${lookup(riskScore[2])}). ${riskScore[3]}/6 Kontrollen sind aktuell aktiviert.`;
    }

    const criticalGaps = source.match(/^Critical gaps?: (.+)\. In practice this would normally require remediation before production use\.$/);
    if (criticalGaps) {
      return `Kritische Lücken: ${criticalGaps[1].split(", ").map(lookup).join(", ")}. In der Praxis würde das normalerweise vor Produktionsnutzung behoben werden müssen.`;
    }

    const missingControls = source.match(/^Missing controls?: (.+)\. Risk is elevated because prevention, containment, or visibility is weaker\.$/);
    if (missingControls) {
      return `Fehlende Kontrollen: ${missingControls[1].split(", ").map(lookup).join(", ")}. Das Risiko ist erhöht, weil Prävention, Begrenzung oder Sichtbarkeit schwächer sind.`;
    }

    const lowerRiskGap = source.match(/^Missing controls?: (.+)\. This is a lower-risk gap, but still not a complete baseline\.$/);
    if (lowerRiskGap) {
      return `Fehlende Kontrollen: ${lowerRiskGap[1].split(", ").map(lookup).join(", ")}. Das ist eine Lücke mit niedrigerem Risiko, aber noch keine vollständige Baseline.`;
    }

    const reviewing = source.match(/^You are reviewing (.+)\. The guided path is at (.+)\.$/);
    if (reviewing) return `Du prüfst gerade ${reviewing[1]}. Der geführte Pfad ist bei ${reviewing[2]}.`;

    const colonStatus = source.match(/^([^:]+): (.+)$/);
    if (colonStatus && (dictionaries.de[colonStatus[1]] || dictionaries.de[colonStatus[2]])) {
      return `${lookup(colonStatus[1])}: ${colonStatus[2].split(", ").map(lookup).join(", ")}`;
    }

    const replacements = [
      [/^Step (\d+) of 6$/, "Schritt $1 von 6"],
      [/^Step (\d+) \/ 6$/, "Schritt $1 / 6"],
      [/^Step (\d+) current$/, "Schritt $1 aktuell"],
      [/^Step (\d+) complete$/, "Schritt $1 abgeschlossen"],
      [/^Step (\d+) upcoming$/, "Schritt $1 ausstehend"],
      [/^Open completed step (\d+): (.+)$/, "Abgeschlossenen Schritt $1 öffnen: $2"],
      [/^Open (.+)$/, "$1 öffnen"],
      [/^Go to Step (\d+)$/, "Zu Schritt $1"],
      [/^Next unfinished step: (.+)\.$/, "Nächster offener Schritt: $1."],
      [/^Next: (.+)$/, "Weiter: $1"],
      [/^(\d+) exercises remaining$/, "$1 Übungen übrig"],
      [/^1 exercise remaining$/, "1 Übung übrig"],
      [/^(\d+)\/6 complete$/, "$1/6 abgeschlossen"],
      [/^(\d+) of 6 guided exercises complete$/, "$1 von 6 geführten Übungen abgeschlossen"],
      [/^Authenticated as (.+)\.$/, "Authentifiziert als $1."],
      [/^Role: (.+)$/, "Rolle: $1"],
      [/^(\d+)\/7 slots filled$/, "$1/7 Slots gefüllt"],
      [/^(\d+)\/7 hardened decisions$/, "$1/7 gehärtete Entscheidungen"],
      [/^Critical blocker: (.+)\. This cannot be considered low risk\.$/, "Kritischer Blocker: $1. Das kann nicht als niedriges Risiko gelten."],
      [/^Critical blockers: (.+)\. This cannot be considered low risk\.$/, "Kritische Blocker: $1. Das kann nicht als niedriges Risiko gelten."],
      [/^Missing critical control: (.+)\. The score is intentionally prevented from dropping into low risk\.$/, "Fehlende kritische Kontrolle: $1. Der Score wird absichtlich daran gehindert, in niedriges Risiko zu fallen."],
      [/^Missing critical controls: (.+)\. The score is intentionally prevented from dropping into low risk\.$/, "Fehlende kritische Kontrollen: $1. Der Score wird absichtlich daran gehindert, in niedriges Risiko zu fallen."],
      [/^(\d+) critical blocker must be fixed first\.$/, "$1 kritischer Blocker muss zuerst behoben werden."],
      [/^(\d+) critical blockers must be fixed first\.$/, "$1 kritische Blocker müssen zuerst behoben werden."]
    ];

    for (const [pattern, replacement] of replacements) {
      if (pattern.test(source)) return source.replace(pattern, replacement);
    }
    return source;
  }

  function translate(source, lang = readLanguage()) {
    const normalized = normalize(source);
    if (!normalized || lang === "en") return normalized;
    return dictionaries[lang]?.[normalized] || dynamicTranslate(normalized, lang);
  }

  function preserveWhitespace(original, translated) {
    const leading = String(original).match(/^\s*/)?.[0] || "";
    const trailing = String(original).match(/\s*$/)?.[0] || "";
    return `${leading}${translated}${trailing}`;
  }

  function shouldSkipNode(node) {
    const parent = node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
    return Boolean(parent?.closest(skipSelector));
  }

  function translateTextNode(node, lang) {
    if (!node.nodeValue || shouldSkipNode(node)) return;
    const normalized = normalize(node.nodeValue);
    if (!normalized) return;
    let source = originalText.get(node);
    if (!source) {
      if (!dictionaries.de[normalized] && dynamicTranslate(normalized, "de") === normalized) return;
      source = normalized;
      originalText.set(node, source);
    }
    const next = lang === "en" ? source : translate(source, lang);
    node.nodeValue = preserveWhitespace(node.nodeValue, next);
  }

  function attributeSource(element, name) {
    const value = element.getAttribute(name);
    if (!value || element.closest(skipSelector)) return null;
    let map = originalAttributes.get(element);
    if (!map) {
      map = {};
      originalAttributes.set(element, map);
    }
    if (!map[name]) {
      const normalized = normalize(value);
      if (!dictionaries.de[normalized] && dynamicTranslate(normalized, "de") === normalized) return null;
      map[name] = normalized;
    }
    return map[name];
  }

  function translateAttributes(root, lang) {
    const elements = root.nodeType === Node.ELEMENT_NODE
      ? [root, ...root.querySelectorAll("*")]
      : [];
    elements.forEach((element) => {
      translatableAttributes.forEach((name) => {
        if (!element.hasAttribute(name)) return;
        const source = attributeSource(element, name);
        if (!source) return;
        element.setAttribute(name, lang === "en" ? source : translate(source, lang));
      });
    });
  }

  function translateRoot(root = document.body) {
    if (!root || applying) return;
    applying = true;
    const lang = readLanguage();
    document.documentElement.lang = lang;
    document.title = lang === "en" ? originalTitle : translate(originalTitle, lang);
    installSwitcher();

    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        return shouldSkipNode(node) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
      }
    });
    let node = walker.nextNode();
    while (node) {
      translateTextNode(node, lang);
      node = walker.nextNode();
    }
    translateAttributes(root, lang);
    updateSwitcher();
    applying = false;
  }

  function scheduleApply() {
    if (applying || pending) return;
    pending = true;
    window.requestAnimationFrame(() => {
      pending = false;
      translateRoot(document.body);
    });
  }

  function setLanguage(lang) {
    if (!supportedLanguages.includes(lang)) return;
    localStorage.setItem(storageKey, lang);
    translateRoot(document.body);
    window.dispatchEvent(new CustomEvent("dbsec:language-changed", { detail: { language: lang } }));
  }

  function updateSwitcher() {
    const lang = readLanguage();
    document.querySelectorAll("[data-language-choice]").forEach((button) => {
      const active = button.dataset.languageChoice === lang;
      button.setAttribute("aria-pressed", String(active));
    });
  }

  function installSwitcher() {
    const headerInner = document.querySelector(".header-inner");
    if (!headerInner || headerInner.querySelector(".language-switcher")) return;
    const switcher = document.createElement("div");
    switcher.className = "language-switcher";
    switcher.setAttribute("aria-label", "Language");
    switcher.innerHTML = `
      <button type="button" data-language-choice="de" aria-pressed="false">DE</button>
      <button type="button" data-language-choice="en" aria-pressed="true">EN</button>
    `;
    switcher.addEventListener("click", (event) => {
      const button = event.target.closest("[data-language-choice]");
      if (button) setLanguage(button.dataset.languageChoice);
    });
    headerInner.appendChild(switcher);
  }

  window.DBSEC_I18N = {
    apply: translateRoot,
    getLanguage: readLanguage,
    setLanguage,
    t: translate
  };

  installSwitcher();
  translateRoot(document.body);

  const observer = new MutationObserver((mutations) => {
    if (applying) return;
    if (mutations.some((mutation) => mutation.type !== "attributes" || translatableAttributes.includes(mutation.attributeName))) {
      scheduleApply();
    }
  });

  if (document.body) {
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
      attributeFilter: translatableAttributes
    });
  }

  document.addEventListener("DOMContentLoaded", () => translateRoot(document.body));
})();
