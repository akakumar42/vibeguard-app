"""German translations for VibeGuard (informal "du", as usual for developer tools).

EXACT maps an English sentence (whitespace squashed) to German. PATTERNS handles sentences with numbers or
names in them: (regex matching the whole English text, German replacement with $1, $2 ...); a captured
group that is itself an EXACT key (like "app" / "website") is translated too.

`python -m scanner.i18n_de` writes static/i18n-de.js, which static/i18n.js uses in the browser.
"""

from __future__ import annotations

import json
from pathlib import Path

PAGES = {
    # ---------------------------------------------------------------- header, sign-in
    "VibeGuard home": "VibeGuard Startseite",
    "scan · explain · fix": "scannen · erklären · beheben",
    "Sign out": "Abmelden",
    "Point VibeGuard at an app or website you built and own. It finds the security holes, bugs and code smells "
    "that AI coding tools leave behind, explains each one in plain English, and can fix them in your code.":
        "Richte VibeGuard auf eine App oder Website, die du gebaut hast und die dir gehört. Es findet die "
        "Sicherheitslücken, Fehler und Code-Smells, die KI-Coding-Tools hinterlassen, erklärt jedes Problem in "
        "einfachen Worten und kann es in deinem Code beheben.",
    "Sign in to scan": "Zum Scannen anmelden",
    "Free scans are counted per person, so we need a verified email. No password needed.":
        "Kostenlose Scans werden pro Person gezählt, deshalb brauchen wir eine bestätigte E-Mail-Adresse. Ein "
        "Passwort ist nicht nötig.",
    "Continue with Google": "Weiter mit Google",
    "or get a sign-in link by email": "oder Anmeldelink per E-Mail",
    "Email": "E-Mail",
    "you@example.com": "du@beispiel.de",
    "Email me a sign-in link": "Anmeldelink per E-Mail senden",
    "Send code": "Code senden",
    "Demo inbox: no email was sent": "Demo-Postfach: Es wurde keine E-Mail gesendet",
    "This server runs in email demo mode, so the code is shown here. With SMTP configured it arrives by email.":
        "Dieser Server läuft im E-Mail-Demomodus, deshalb wird der Code hier angezeigt. Mit eingerichtetem SMTP "
        "kommt er per E-Mail.",
    "6-digit code": "6-stelliger Code",
    "Sign in": "Anmelden",
    "Send a new code": "Neuen Code senden",
    "Use a different email": "Andere E-Mail-Adresse verwenden",
    "Could not load the sign-in library": "Die Anmeldung konnte nicht geladen werden",
    "Unlimited scans on this account.": "Unbegrenzte Scans für dieses Konto.",
    # ---------------------------------------------------------------- tabs and forms
    "Android app": "Android-App",
    "Website": "Website",
    "Fix my code": "Meinen Code beheben",
    "Choose an APK file": "APK-Datei auswählen",
    "Drop your .apk file here": "Zieh deine .apk-Datei hierher",
    "or click to choose one (up to": "oder klicke, um eine auszuwählen (bis zu",
    "MB)": "MB)",
    "I own this app, or I have permission to test it.":
        "Diese App gehört mir, oder ich habe die Erlaubnis, sie zu testen.",
    "Free: see how many problems your app has and what they are. The $29 report shows where each one is and how to fix it.":
        "Kostenlos: Sieh, wie viele Probleme deine App hat und welche. Der Bericht für 29 $ zeigt, wo jedes steckt "
        "und wie du es behebst.",
    "Decompiler": "Decompiler",
    "Fast · jadx": "Schnell · jadx",
    "Deep · VibeGuard engine": "Gründlich · VibeGuard-Engine",
    "Scan app": "App scannen",
    "or view an example report": "oder einen Beispielbericht ansehen",
    "About 1 minute. Decompiles the whole app in one pass.":
        "Etwa 1 Minute. Dekompiliert die ganze App in einem Durchgang.",
    "About 13 minutes. The VibeGuard deep engine decompiles each method separately and records where every fact "
    "came from. Same issues as jadx.":
        "Etwa 13 Minuten. Die gründliche VibeGuard-Engine dekompiliert jede Methode einzeln und hält fest, woher "
        "jede Angabe stammt. Dieselben Probleme wie mit jadx.",
    "(The deep engine is not installed on this server.)":
        "(Die gründliche Engine ist auf diesem Server nicht installiert.)",
    "Website address": "Website-Adresse",
    "https://myapp.com": "https://meine-app.de",
    "We load the page like a visitor would, check the code it sends to browsers and the server's security settings. "
    "Nothing is changed on your site. You can only scan websites you own.":
        "Wir laden die Seite wie ein Besucher und prüfen den Code, den sie an Browser sendet, sowie die "
        "Sicherheitseinstellungen des Servers. An deiner Website wird nichts verändert. Du kannst nur Websites "
        "scannen, die dir gehören.",
    "Just trying VibeGuard?": "Willst du VibeGuard nur ausprobieren?",
    "Scan the built-in demo site": "Scanne die eingebaute Demo-Website",
    "(it has problems planted on purpose).": "(sie enthält absichtlich eingebaute Probleme).",
    "Prove you own this site": "Beweise, dass dir diese Website gehört",
    "Easiest: add one tag to your homepage": "Am einfachsten: ein Tag auf deiner Startseite einfügen",
    "(works even if the rest of your site needs a login)":
        "(funktioniert auch, wenn der Rest deiner Website eine Anmeldung braucht)",
    "Copy": "Kopieren",
    "Put it inside": "Füge es ein in",
    "of": "von",
    ". In Next.js (app folder), add this to": ". In Next.js (app-Ordner) fügst du das hier hinzu:",
    "Or upload a file instead": "Oder stattdessen eine Datei hochladen",
    "Create": "Erstelle",
    "(or a": "(oder einen",
    "folder next to your index.html) containing only this line, so it opens at":
        "-Ordner neben deiner index.html) mit nur dieser Zeile, sodass sie erreichbar ist unter",
    "If your site sends every page to a login screen, let": "Wenn deine Website jede Seite zur Anmeldung umleitet, lass",
    "through your middleware.": "in deiner Middleware durch.",
    "Then deploy and press": "Dann veröffentlichen und klicke auf",
    "Scan website": "Website scannen",
    "again. You can remove it afterwards.": "erneut. Danach kannst du es wieder entfernen.",
    "I own this website, or I have permission to test it.":
        "Diese Website gehört mir, oder ich habe die Erlaubnis, sie zu testen.",
    "Free: see how many problems your site has and what they are. The $29 report shows where each one is and how to fix it.":
        "Kostenlos: Sieh, wie viele Probleme deine Website hat und welche. Der Bericht für 29 $ zeigt, wo jedes "
        "steckt und wie du es behebst.",
    "How do I prove I own it?": "Wie beweise ich, dass sie mir gehört?",
    "No proof needed": "Kein Nachweis nötig",
    "This site runs on your own computer, so you can scan it straight away.":
        "Diese Website läuft auf deinem eigenen Computer, du kannst sie also sofort scannen.",
    "This site is on this server's trusted list, so you can scan it straight away.":
        "Diese Website steht auf der Vertrauensliste dieses Servers, du kannst sie also sofort scannen.",
    "We couldn't confirm you own this site yet": "Wir konnten noch nicht bestätigen, dass dir diese Website gehört",
    "Before we scan a website we check that its owner added a small tag or file to it. It takes a minute:":
        "Bevor wir eine Website scannen, prüfen wir, ob ihr Eigentümer ein kleines Tag oder eine Datei hinzugefügt "
        "hat. Das dauert eine Minute:",
    "Enter the website address first": "Gib zuerst die Website-Adresse ein",
    "Choose a .zip of your project": "Wähle eine .zip-Datei deines Projekts",
    "Drop your project's .zip here": "Zieh die .zip-Datei deines Projekts hierher",
    "or click to choose one (up to 50 MB, leave out build folders). Signing keys and local secret files are "
    "dropped automatically.":
        "oder klicke, um eine auszuwählen (bis zu 50 MB, ohne Build-Ordner). Signaturschlüssel und lokale "
        "geheime Dateien werden automatisch weggelassen.",
    "We scan your source code with the same rules as the app and website scans. For $99 we fix every critical issue "
    "and warning, and keep a fix only when a re-scan proves the problem is gone. Works for Android apps (Java, "
    "Kotlin, AndroidManifest.xml) and web apps (JavaScript, TypeScript, React, Next.js).":
        "Wir scannen deinen Quellcode mit denselben Regeln wie die App- und Website-Scans. Für 99 $ beheben wir jedes kritische "
        "Problem und jede Warnung und behalten eine Korrektur nur, wenn ein erneuter Scan beweist, dass das Problem "
        "weg ist. Funktioniert für Android-Apps (Java, Kotlin, AndroidManifest.xml) und Web-Apps (JavaScript, "
        "TypeScript, React, Next.js).",
    "I own this code, or I have permission to change it.":
        "Dieser Code gehört mir, oder ich habe die Erlaubnis, ihn zu ändern.",
    "Scan source code": "Quellcode scannen",
    "Please choose a .zip of your project": "Bitte wähle eine .zip-Datei deines Projekts",
    "Please choose a file ending in .apk": "Bitte wähle eine Datei mit der Endung .apk",
    # ---------------------------------------------------------------- progress, errors
    "Scanning…": "Wird gescannt…",
    "Keep this tab open until the report appears.": "Lass diesen Tab offen, bis der Bericht erscheint.",
    "Cancel scan": "Scan abbrechen",
    "Stops the scan straight away. No free scan is used.":
        "Stoppt den Scan sofort. Es wird kein kostenloser Scan verbraucht.",
    "That didn't work": "Das hat nicht geklappt",
    "Try again": "Erneut versuchen",
    "Uploading the app": "App wird hochgeladen",
    "VibeGuard deep engine: reverse-engineering the app method by method (the longest step)":
        "Gründliche VibeGuard-Engine: Die App wird Methode für Methode zurückentwickelt (der längste Schritt)",
    "Unpacking and decompiling the code": "Code wird entpackt und dekompiliert",
    "Mapping permissions, servers and libraries": "Berechtigungen, Server und Bibliotheken werden erfasst",
    "Scanning for security problems and bugs": "Suche nach Sicherheitsproblemen und Fehlern",
    "Writing plain-English explanations": "Verständliche Erklärungen werden geschrieben",
    "Uploading your project": "Dein Projekt wird hochgeladen",
    "Unpacking it safely": "Es wird sicher entpackt",
    "Scanning the code with the same rules as the app scan": "Code wird mit denselben Regeln wie beim App-Scan geprüft",
    "Checking the website's security settings": "Sicherheitseinstellungen der Website werden geprüft",
    "Loading the page and capturing its code": "Seite wird geladen und ihr Code erfasst",
    "Scanning the code for security problems": "Code wird auf Sicherheitsprobleme geprüft",
    "Taking longer than usual. Still working…": "Dauert länger als üblich. Läuft noch…",
    "Couldn't reach the scanner. Is the server still running?": "Der Scanner ist nicht erreichbar. Läuft der Server noch?",
    "The scan took too long and was stopped. Try again, or choose the Fast · jadx decompiler.":
        "Der Scan hat zu lange gedauert und wurde gestoppt. Versuch es erneut oder wähle den Decompiler Schnell · jadx.",
    "The example report couldn't be loaded.": "Der Beispielbericht konnte nicht geladen werden.",
    "Scan cancelled. No free scan was used.": "Scan abgebrochen. Es wurde kein kostenloser Scan verbraucht.",
    "Your deep scan is still running": "Dein gründlicher Scan läuft noch",
    "Your scan is still running": "Dein Scan läuft noch",
    "You can leave this page or switch apps. The report opens here when it's done.":
        "Du kannst diese Seite verlassen oder die App wechseln. Der Bericht öffnet sich hier, sobald er fertig ist.",
    "The scan is no longer running. Please start it again.": "Der Scan läuft nicht mehr. Bitte starte ihn erneut.",
    "Couldn't copy - select the text instead": "Kopieren nicht möglich – markiere den Text stattdessen",
    "Copied": "Kopiert",
    # ---------------------------------------------------------------- report
    "Fix before you release": "Vor der Veröffentlichung beheben",
    "Fix soon": "Bald beheben",
    "Clean up when you can": "Aufräumen, wenn du Zeit hast",
    "Critical": "Kritisch",
    "Warning": "Warnung",
    "Warnings": "Warnungen",
    "Smell": "Smell",
    "Code smells": "Code-Smells",
    "Smells": "Smells",
    "Example report · F-Droid, an open-source app store": "Beispielbericht · F-Droid, ein Open-Source-App-Store",
    "✓ Paid · full report unlocked": "✓ Bezahlt · vollständiger Bericht freigeschaltet",
    "Copy all fixes for my AI tool": "Alle Korrekturen für mein KI-Tool kopieren",
    "Download text": "Als Text herunterladen",
    "Download JSON": "Als JSON herunterladen",
    "Scan another app": "Eine andere App scannen",
    "AI explanations were not used for this report.": "Für diesen Bericht wurden keine KI-Erklärungen verwendet.",
    "The issues and their severity are exactly the same as with AI - they come from fixed scanner rules.":
        "Die Probleme und ihr Schweregrad sind genau dieselben wie mit KI – sie stammen aus festen Scanner-Regeln.",
    "The descriptions below are the rules' standard wording instead of explanations written for your code.":
        "Die Beschreibungen unten sind der Standardtext der Regeln statt Erklärungen für deinen Code.",
    "How this website works": "So funktioniert diese Website",
    "How this app works": "So funktioniert diese App",
    "What it does, step by step": "Was sie tut, Schritt für Schritt",
    "Personal data it can access": "Persönliche Daten, auf die sie zugreifen kann",
    "Who it talks to": "Mit wem sie kommuniziert",
    "Nothing found.": "Nichts gefunden.",
    "💡 AI suggestions": "💡 KI-Vorschläge",
    "Possible problems the AI noticed while reading the code. No scanner rule confirms them, so check them before acting.":
        "Mögliche Probleme, die der KI beim Lesen des Codes aufgefallen sind. Keine Scanner-Regel bestätigt sie, "
        "prüfe sie also, bevor du handelst.",
    "scanner rule text (no AI)": "Text der Scanner-Regeln (ohne KI)",
    "How to fix": "So behebst du es",
    "Where in the code": "Wo im Code",
    "AI review: probably a false alarm here": "KI-Prüfung: hier wahrscheinlich ein Fehlalarm",
    "AI review: some of these places are probably false alarms": "KI-Prüfung: einige dieser Stellen sind wahrscheinlich Fehlalarme",
    "Still counted until a person checks it.": "Wird weiter gezählt, bis ein Mensch es geprüft hat.",
    "Not counted.": "Wird nicht gezählt.",
    "🔕 Probably false alarms": "🔕 Wahrscheinlich Fehlalarme",
    "The scanner rules flagged these, but the AI read the code and judged them safe. Check them once before you ignore them.":
        "Die Scanner-Regeln haben diese Stellen markiert, aber die KI hat den Code gelesen und sie als sicher eingestuft. "
        "Prüfe sie einmal, bevor du sie ignorierst.",
    "Not counted: 1 probable false alarm (listed below the issues)":
        "Nicht gezählt: 1 wahrscheinlicher Fehlalarm (unter den Problemen aufgeführt)",
    "Possible fix": "Mögliche Korrektur",
    "No issues with suggested fixes were found.": "Es wurden keine Probleme mit Korrekturvorschlägen gefunden.",
    "Opening your report…": "Dein Bericht wird geöffnet…",
    "A newly paid report is written by the AI first, which takes about a minute.":
        "Ein frisch bezahlter Bericht wird zuerst von der KI geschrieben, das dauert etwa eine Minute.",
    "Writing plain-English explanations for your issues": "Verständliche Erklärungen für deine Probleme werden geschrieben",
    "This report could not be opened.": "Dieser Bericht konnte nicht geöffnet werden.",
    "🔒 Where it is, why it matters and how to fix it": "🔒 Wo es steckt, warum es wichtig ist und wie du es behebst",
    "Get the full report": "Vollständigen Bericht holen",
    "Demo payments · no real money": "Demo-Zahlungen · kein echtes Geld",
    "Coming soon": "Demnächst",
    "Upload your source code": "Quellcode hochladen",
    "Checkout failed": "Bezahlung fehlgeschlagen",
    "You scanned this exact file before, so this is the saved result. No free scan was used.":
        "Du hast genau diese Datei schon gescannt, das ist also das gespeicherte Ergebnis. Es wurde kein "
        "kostenloser Scan verbraucht.",
    "the fast engine (jadx)": "der schnellen Engine (jadx)",
    "the VibeGuard deep engine": "der gründlichen VibeGuard-Engine",
    "VibeGuard's direct fetch": "dem direkten Abruf von VibeGuard",
    "Bug report": "Fehlerbericht",
    "Bug fixing": "Fehlerbehebung",
    "Code improvement": "Code-Verbesserung",
    "Where every issue is, plain-English explanations, how to fix each one, AI suggestions":
        "Wo jedes Problem steckt, verständliche Erklärungen, wie du jedes behebst, KI-Vorschläge",
    "Fixes for every critical issue and warning in your source code, re-scanned to prove they are gone":
        "Korrekturen für jedes kritische Problem und jede Warnung in deinem Quellcode, durch erneuten Scan bewiesen",
    "Everything in Secure & Auto-Fix, plus code smells fixed, a structure review with refactoring plans, and a ready-to-open pull request":
        "Alles aus Secure & Auto-Fix, dazu behobene Code-Smells, eine Strukturprüfung mit Refactoring-Plänen und "
        "ein fertiger Pull Request",
    # ---------------------------------------------------------------- source scans and fixing
    "No problems found in your code": "In deinem Code wurden keine Probleme gefunden",
    "There are no critical issues or warnings to fix.": "Es gibt keine kritischen Probleme oder Warnungen zu beheben.",
    "You scanned this exact project before, so this is the saved result. No free scan was used.":
        "Du hast genau dieses Projekt schon gescannt, das ist also das gespeicherte Ergebnis. Es wurde kein "
        "kostenloser Scan verbraucht.",
    "You revoke the key": "Du sperrst den Schlüssel",
    "Both packages fix this": "Beide Pakete beheben das",
    "Deep Architecture Audit fixes this": "Das Deep Architecture Audit behebt das",
    "Deep Architecture Audit reviews this": "Das Deep Architecture Audit prüft das",
    "📐 Structure": "📐 Struktur",
    "Fix it": "Beheben",
    "Scan another project": "Ein anderes Projekt scannen",
    "Fixing your code…": "Dein Code wird korrigiert…",
    "Each fix is re-scanned before it is kept. This takes a few minutes; you can leave this tab open.":
        "Jede Korrektur wird erneut gescannt, bevor sie behalten wird. Das dauert ein paar Minuten; du kannst den Tab offen lassen.",
    "The fixing run could not be checked.": "Der Korrekturlauf konnte nicht abgefragt werden.",
    "Re-scanned with the same rules": "Mit denselben Regeln erneut gescannt",
    "Syntax checked": "Syntax geprüft",
    "No constructor or public method changed": "Kein Konstruktor und keine öffentliche Methode geändert",
    "No new problems": "Keine neuen Probleme",
    "Patch applies cleanly to your upload": "Der Patch lässt sich sauber auf deinen Upload anwenden",
    "Patch did not apply cleanly": "Der Patch ließ sich nicht sauber anwenden",
    "Not compiled here: build and test before release": "Hier nicht kompiliert: vor der Veröffentlichung bauen und testen",
    "Download fixes.patch": "fixes.patch herunterladen",
    "Download fixed project (.zip)": "Korrigiertes Projekt herunterladen (.zip)",
    "Download PR description": "PR-Beschreibung herunterladen",
    "Fixed ✓": "Behoben ✓",
    "Partly fixed": "Teilweise behoben",
    "Needs a manual fix": "Muss von Hand behoben werden",
    "🔧 Changes": "🔧 Änderungen",
    "Show the change": "Änderung anzeigen",
    "🔑 Do this yourself": "🔑 Das machst du selbst",
    "📐 Structure review": "📐 Strukturprüfung",
    "Suggestion · not applied": "Vorschlag · nicht angewendet",
    "Show a sketch of the new shape": "Skizze der neuen Form anzeigen",
    "🔀 Pull request": "🔀 Pull Request",
    "ready to open": "bereit zum Öffnen",
    "In your project folder, with fixes.patch and commit-message.txt downloaded:":
        "In deinem Projektordner, mit heruntergeladener fixes.patch und commit-message.txt:",
    "Copy PR description": "PR-Beschreibung kopieren",
    "Download commit-message.txt": "commit-message.txt herunterladen",
    "Preview the PR description": "Vorschau der PR-Beschreibung",
    "(cleaned up in the Deep Architecture Audit)": "(werden im Deep Architecture Audit aufgeräumt)",
    "Measured with SonarSource's default limits. Suggestions are written by the AI and are not applied: a "
    "restructure can only be proven safe by compiling the app and running its tests.":
        "Gemessen mit den Standardgrenzen von SonarSource. Die Vorschläge schreibt die KI, und sie werden nicht "
        "angewendet: Ein Umbau lässt sich nur durch Kompilieren der App und Ausführen ihrer Tests als sicher beweisen.",
    "Each change was re-scanned with the same rules and checked for syntax errors, and the patch was checked to "
    "apply cleanly to the code you uploaded. The project was not compiled or tested here: build it and run your "
    "tests before releasing. Review every change; the AI wrote the edits and the scanner only proves the listed "
    "problems are gone.":
        "Jede Änderung wurde mit denselben Regeln erneut gescannt und auf Syntaxfehler geprüft, und es wurde "
        "geprüft, dass sich der Patch sauber auf deinen hochgeladenen Code anwenden lässt. Das Projekt wurde hier "
        "weder kompiliert noch getestet: Bau es und führe deine Tests aus, bevor du veröffentlichst. Prüfe jede "
        "Änderung; die KI hat die Änderungen geschrieben, und der Scanner beweist nur, dass die genannten Probleme "
        "weg sind.",
    "Revoke this key in the provider's dashboard and create a new one: it is already inside copies of your app, "
    "so editing the code does not make it secret again. Then load the new key from your server at runtime (or, "
    "for keys that are meant to be public, restrict them by app signature) instead of writing it into the code.":
        "Sperre diesen Schlüssel im Dashboard des Anbieters und erstelle einen neuen: Er steckt bereits in Kopien "
        "deiner App, eine Änderung am Code macht ihn also nicht wieder geheim. Lade den neuen Schlüssel dann zur "
        "Laufzeit von deinem Server (oder beschränke Schlüssel, die öffentlich sein sollen, auf deine App-Signatur), "
        "statt ihn in den Code zu schreiben.",
    "Already gone after an earlier fix in the same file.": "Schon durch eine frühere Korrektur in derselben Datei verschwunden.",
    "The file is too large to fix automatically.": "Die Datei ist zu groß, um sie automatisch zu korrigieren.",
    "The scanner still finds the problem after the edit.": "Der Scanner findet das Problem nach der Änderung immer noch.",
    "The edited file no longer parses (syntax error).": "Die geänderte Datei lässt sich nicht mehr einlesen (Syntaxfehler).",
    # ---------------------------------------------------------------- disclaimers
    "This is an automated scan of the app's decompiled code. Issues and their severity come from fixed scanner "
    "rules, so the same app always gets the same result; the plain-English wording and the 'AI suggestions' "
    "section are written by an AI and can be wrong. The scan can miss problems and can raise false alarms, so "
    "treat it as a starting point for review, not a guarantee that the app is safe.":
        "Dies ist ein automatischer Scan des dekompilierten Codes der App. Probleme und ihr Schweregrad stammen aus "
        "festen Scanner-Regeln, dieselbe App bekommt also immer dasselbe Ergebnis; die verständlichen Erklärungen "
        "und der Abschnitt „KI-Vorschläge“ werden von einer KI geschrieben und können falsch sein. Der Scan kann "
        "Probleme übersehen und Fehlalarme auslösen. Betrachte ihn als Ausgangspunkt für eine Prüfung, nicht als "
        "Garantie, dass die App sicher ist.",
    "This is an automated scan of the code this website sends to browsers and of its server responses. Issues "
    "and their severity come from fixed scanner rules, so the same site always gets the same result; the "
    "plain-English wording and the 'AI suggestions' section are written by an AI and can be wrong. The scan can "
    "miss problems and can raise false alarms, so treat it as a starting point for review, not a guarantee that "
    "the app is safe.":
        "Dies ist ein automatischer Scan des Codes, den diese Website an Browser sendet, und der Antworten ihres "
        "Servers. Probleme und ihr Schweregrad stammen aus festen Scanner-Regeln, dieselbe Website bekommt also "
        "immer dasselbe Ergebnis; die verständlichen Erklärungen und der Abschnitt „KI-Vorschläge“ werden von "
        "einer KI geschrieben und können falsch sein. Der Scan kann Probleme übersehen und Fehlalarme auslösen. "
        "Betrachte ihn als Ausgangspunkt für eine Prüfung, nicht als Garantie, dass die Website sicher ist.",
    # ---------------------------------------------------------------- checkout page
    "VibeGuard Checkout": "VibeGuard Bezahlung",
    "checkout": "Bezahlung",
    "Demo checkout: no real payment": "Demo-Bezahlung: keine echte Zahlung",
    "This is a hackathon demo. No card details are collected and no money is taken. Pressing Pay marks the order as paid.":
        "Dies ist eine Hackathon-Demo. Es werden keine Kartendaten erfasst und kein Geld abgebucht. Ein Klick auf "
        "Bezahlen markiert die Bestellung als bezahlt.",
    "Loading order…": "Bestellung wird geladen…",
    "Pay": "Bezahlen",
    "Cancel and go back": "Abbrechen und zurück",
    "Scan": "Scan",
    "Issues found": "Gefundene Probleme",
    "Result fingerprint": "Ergebnis-Fingerabdruck",
    "Order": "Bestellung",
    "Total": "Summe",
    "Payment received. Opening your full report…": "Zahlung erhalten. Dein vollständiger Bericht wird geöffnet…",
    "This order was cancelled.": "Diese Bestellung wurde storniert.",
    "Back to the free result": "Zurück zum kostenlosen Ergebnis",
    "Something went wrong": "Etwas ist schiefgelaufen",
    "Order not found": "Bestellung nicht gefunden",
}

LANDING = {
    "How it works": "So funktioniert es",
    "Why trust it": "Warum du ihm trauen kannst",
    "Pricing": "Preise",
    "Scan free": "Kostenlos scannen",
    "Open VibeGuard": "VibeGuard öffnen",
    "Open VibeGuard →": "VibeGuard öffnen →",
    "Security check for vibe-coded apps": "Sicherheitscheck für vibe-gecodete Apps",
    "Your AI wrote the app.": "Deine KI hat die App geschrieben.",
    "checks it.": "prüft sie.",
    "Upload your Android app, point it at your website, or give it your code. VibeGuard finds the security "
    "holes, bugs and messy code that AI coding tools leave behind, explains each one in plain English, and "
    "fixes them, with a re-scan that proves each fix worked.":
        "Lade deine Android-App hoch, gib die Adresse deiner Website an oder deinen Code. VibeGuard findet die "
        "Sicherheitslücken, Fehler und unordentlichen Code, die KI-Coding-Tools hinterlassen, erklärt alles in "
        "einfachen Worten und behebt es – mit einem erneuten Scan, der beweist, dass jede Korrektur funktioniert.",
    "Scan your app free →": "Deine App kostenlos scannen →",
    "See a real report": "Einen echten Bericht ansehen",
    "Free: 5 scans a day · no card needed · sign in with Google":
        "Kostenlos: 5 Scans pro Tag · keine Karte nötig · Anmeldung mit Google",
    "Android .apk": "Android-.apk",
    "Websites": "Websites",
    "Java, Kotlin, JS & TS code": "Java-, Kotlin-, JS- und TS-Code",
    "A real VibeGuard report": "Ein echter VibeGuard-Bericht",
    "Real scan · F-Droid (open-source app store)": "Echter Scan · F-Droid (Open-Source-App-Store)",
    "In plain English": "In einfachen Worten",
    "A specially crafted zip could write files outside the folder it should go into and overwrite parts of the app.":
        "Eine präparierte ZIP-Datei könnte Dateien außerhalb des vorgesehenen Ordners schreiben und Teile der App "
        "überschreiben.",
    "What it checks": "Was es prüft",
    "Three ways in. One plain-English report.": "Drei Wege hinein. Ein verständlicher Bericht.",
    "Whatever you built with, VibeGuard looks at what really ships to your users.":
        "Egal womit du gebaut hast: VibeGuard schaut sich an, was wirklich bei deinen Nutzern ankommt.",
    "Android apps": "Android-Apps",
    "Drop in your .apk. VibeGuard takes it apart and checks the app's own code, its settings and its signature.":
        "Leg deine .apk ab. VibeGuard nimmt sie auseinander und prüft den eigenen Code der App, ihre Einstellungen "
        "und ihre Signatur.",
    "Leaked keys and passwords": "Geleakte Schlüssel und Passwörter",
    "Broken HTTPS and weak encryption": "Fehlerhaftes HTTPS und schwache Verschlüsselung",
    "Risky permissions and debug builds": "Riskante Berechtigungen und Debug-Builds",
    "Give it your live URL. It opens the site like a visitor and checks the code your browser downloads.":
        "Gib deine Live-URL an. VibeGuard öffnet die Website wie ein Besucher und prüft den Code, den dein Browser lädt.",
    "Admin keys shipped to the browser": "Admin-Schlüssel, die an den Browser gehen",
    "Exposed .env and .git files": "Offen liegende .env- und .git-Dateien",
    "Missing security headers": "Fehlende Sicherheits-Header",
    "Your source code": "Dein Quellcode",
    "Upload a zip of your project and VibeGuard fixes the problems in your code for you: Android (Java, Kotlin) "
    "or web (JavaScript, TypeScript).":
        "Lade eine ZIP-Datei deines Projekts hoch, und VibeGuard behebt die Probleme in deinem Code: Android (Java, "
        "Kotlin) oder Web (JavaScript, TypeScript).",
    "A patch you apply with one command": "Ein Patch, den du mit einem Befehl anwendest",
    "A ready-to-open pull request": "Ein fertiger Pull Request",
    "Signing keys are never stored": "Signaturschlüssel werden nie gespeichert",
    "From upload to fixed in minutes": "Vom Upload zur Korrektur in Minuten",
    "Upload": "Hochladen",
    "Your .apk, your website address, or a zip of your code. Only things you own.":
        "Deine .apk, deine Website-Adresse oder eine ZIP-Datei deines Codes. Nur, was dir gehört.",
    "Proven open tools (Semgrep, Gitleaks, jadx) check it against fixed rules mapped to OWASP and CWE.":
        "Bewährte offene Tools (Semgrep, Gitleaks, jadx) prüfen es mit festen Regeln nach OWASP und CWE.",
    "Understand": "Verstehen",
    "AI explains every issue in plain English: what it is, where it lives, and why it matters.":
        "Die KI erklärt jedes Problem in einfachen Worten: was es ist, wo es steckt und warum es wichtig ist.",
    "Fix": "Beheben",
    "VibeGuard changes your code and keeps a fix only when a re-scan proves the problem is gone.":
        "VibeGuard ändert deinen Code und behält eine Korrektur nur, wenn ein erneuter Scan beweist, dass das Problem weg ist.",
    "The AI explains. The rules decide.": "Die KI erklärt. Die Regeln entscheiden.",
    "AI tools are great at writing code and bad at grading it. So in VibeGuard, the AI never decides what "
    "counts as a problem or how serious it is.":
        "KI-Tools können großartig Code schreiben, ihn aber schlecht bewerten. Deshalb entscheidet bei VibeGuard "
        "nie die KI, was als Problem zählt oder wie schwer es wiegt.",
    "Same app, same result.": "Gleiche App, gleiches Ergebnis.",
    "Every report has a fingerprint. Scan the same file again and you get the same issues.":
        "Jeder Bericht hat einen Fingerabdruck. Scanne dieselbe Datei erneut, und du bekommst dieselben Probleme.",
    "Severity from a fixed policy": "Schweregrad aus einer festen Richtlinie",
    ", mapped to OWASP MASVS (apps), OWASP ASVS (websites) and CWE.":
        ", zugeordnet zu OWASP MASVS (Apps), OWASP ASVS (Websites) und CWE.",
    "Every fix is proven": "Jede Korrektur ist bewiesen",
    ": re-scanned, syntax-checked, and rejected if it changes how other code uses yours.":
        ": erneut gescannt, auf Syntax geprüft und verworfen, wenn sie ändert, wie anderer Code deinen verwendet.",
    "Honest about limits.": "Ehrlich bei den Grenzen.",
    "If something wasn't checked or couldn't be fixed safely, the report says so.":
        "Wenn etwas nicht geprüft oder nicht sicher behoben werden konnte, steht es im Bericht.",
    "An example fix": "Eine Beispielkorrektur",
    "issues found in F-Droid": "Probleme in F-Droid gefunden",
    "real open-source app · about 40 seconds": "echte Open-Source-App · etwa 40 Sekunden",
    "issues fixed and proven": "Probleme behoben und bewiesen",
    "our demo project · Java + Kotlin · about 2 minutes": "unser Demoprojekt · Java + Kotlin · etwa 2 Minuten",
    "new problems introduced": "neue Probleme eingeführt",
    "every fix is re-scanned before it is kept": "jede Korrektur wird vor dem Übernehmen erneut gescannt",
    "Start free. Pay once when you want the details.": "Starte kostenlos. Zahl einmal, wenn du die Details willst.",
    "No subscription. Every scan is free to try, and you only pay for the report or the fixes you need.":
        "Kein Abo. Jeder Scan ist kostenlos zum Ausprobieren, und du zahlst nur für den Bericht oder die "
        "Korrekturen, die du brauchst.",
    "Free scan": "Kostenloser Scan",
    "See how many problems your app has and what they are.": "Sieh, wie viele Probleme deine App hat und welche.",
    "Counts and titles of every issue": "Anzahl und Titel jedes Problems",
    "scans a day": "Scans pro Tag",
    "Rescanning the same app is free": "Dieselbe App erneut zu scannen ist kostenlos",
    "Start free": "Kostenlos starten",
    "one-off": "einmalig",
    "The full plain-English report.": "Der vollständige, verständliche Bericht.",
    "Where every issue is": "Wo jedes Problem steckt",
    "Why it matters and how to fix it": "Warum es wichtig ist und wie du es behebst",
    "Copy-paste prompts for your AI tool": "Prompts zum Kopieren für dein KI-Tool",
    "Scan, then unlock": "Scannen, dann freischalten",
    "We fix the critical issues and warnings in your code.": "Wir beheben die kritischen Probleme und Warnungen in deinem Code.",
    "Each fix proven by a re-scan": "Jede Korrektur durch erneuten Scan bewiesen",
    "A patch and the fixed project": "Ein Patch und das korrigierte Projekt",
    "Android and web projects": "Android- und Webprojekte",
    "Upload your code": "Deinen Code hochladen",
    "Everything in Bug fixing, and more.": "Alles aus der Fehlerbehebung und mehr.",
    "Code smells fixed too": "Auch Code-Smells behoben",
    "Structure review with refactoring plans": "Strukturprüfung mit Refactoring-Plänen",
    "Hackathon demo: payments are simulated, so no real money is taken.":
        "Hackathon-Demo: Zahlungen werden simuliert, es wird kein echtes Geld abgebucht.",
    "Questions": "Fragen",
    "Good to know": "Gut zu wissen",
    "Is this just an AI guessing?": "Rät hier nur eine KI?",
    "No. Problems are found by established scanners (Semgrep, Gitleaks, jadx, and Google's apksig for app "
    "signatures) using fixed rules. The severity comes from a fixed policy, not from the AI. The AI only writes "
    "the plain-English explanations and the code edits, and every edit has to pass a re-scan before it is kept.":
        "Nein. Probleme werden von etablierten Scannern (Semgrep, Gitleaks, jadx und Googles apksig für "
        "App-Signaturen) mit festen Regeln gefunden. Der Schweregrad kommt aus einer festen Richtlinie, nicht von "
        "der KI. Die KI schreibt nur die verständlichen Erklärungen und die Code-Änderungen, und jede Änderung muss "
        "einen erneuten Scan bestehen, bevor sie behalten wird.",
    "Do I have to upload my source code?": "Muss ich meinen Quellcode hochladen?",
    "Only if you want us to fix things. The free scan and the $9 report work from your .apk or your website "
    "address alone. For fixing, the app module is usually enough. Signing keys, local.properties and .env files "
    "are dropped automatically, and uploads are deleted after 24 hours.":
        "Nur, wenn wir etwas beheben sollen. Der kostenlose Scan und der Bericht für 9 $ funktionieren allein mit "
        "deiner .apk oder deiner Website-Adresse. Zum Beheben reicht meist das App-Modul. Signaturschlüssel, "
        "local.properties und .env-Dateien werden automatisch weggelassen, und Uploads werden nach 24 Stunden gelöscht.",
    "Can I scan any app or website?": "Kann ich jede App oder Website scannen?",
    "Only ones you own or have permission to test. You confirm this before every scan, and websites need a small "
    "verification file before we scan them (sites on your own computer are exempt).":
        "Nur solche, die dir gehören oder die du testen darfst. Das bestätigst du vor jedem Scan, und Websites "
        "brauchen vor dem Scan eine kleine Bestätigungsdatei (Websites auf deinem eigenen Computer ausgenommen).",
    "Which languages does it fix?": "Welche Sprachen behebt es?",
    "Android projects (Java, Kotlin, AndroidManifest.xml) and web projects (JavaScript and TypeScript, including "
    "React and Next.js). Live websites are also checked through the code they send to browsers and the server's "
    "security settings.":
        "Android-Projekte (Java, Kotlin, AndroidManifest.xml) und Webprojekte (JavaScript und TypeScript, auch "
        "React und Next.js). Live-Websites werden außerdem über den Code geprüft, den sie an Browser senden, und "
        "über die Sicherheitseinstellungen des Servers.",
    "Will the fixes break my app?": "Machen die Korrekturen meine App kaputt?",
    "Each fix is re-scanned and syntax-checked, and rejected if it changes how other code calls yours. VibeGuard "
    "does not compile or run your app, so please build it and run your tests before releasing; the report reminds "
    "you, and flags any change that needs data migration.":
        "Jede Korrektur wird erneut gescannt und auf Syntax geprüft und verworfen, wenn sie ändert, wie anderer Code "
        "deinen aufruft. VibeGuard kompiliert und startet deine App nicht, bau sie also und führe deine Tests aus, "
        "bevor du veröffentlichst; der Bericht erinnert dich daran und markiert jede Änderung, die eine "
        "Datenmigration braucht.",
    "Ship it with confidence.": "Veröffentliche mit gutem Gefühl.",
    "Find out what your AI left behind before your users do.":
        "Finde heraus, was deine KI hinterlassen hat, bevor es deine Nutzer tun.",
    "Only scan apps you own or are authorized to test.": "Scanne nur Apps, die dir gehören oder die du testen darfst.",
    "✓ re-scanned: problem gone ✓ no new problems": "✓ erneut gescannt: Problem weg ✓ keine neuen Probleme",
    "✓ still parses ✓ no public method changed": "✓ weiterhin lesbar ✓ keine öffentliche Methode geändert",
}

# Scanner rules: rule id -> (title, why it matters, how to fix). Same keys as scanner/policy.RULES.
RULES = {
    "trust-all-certificates": ("Die App akzeptiert gefälschte Sicherheitszertifikate",
        "Die App vertraut jedem Serverzertifikat, sodass sich jemand im selben WLAN als dein Server ausgeben und alles lesen oder ändern kann, was die App sendet – auch Passwörter.",
        "Entferne den eigenen `TrustManager`, der jedes Zertifikat akzeptiert, und nutze den Systemstandard; für einen selbstsignierten Server eine Network Security Config, die genau dieses Zertifikat festlegt."),
    "hostname-verifier-allow-all": ("Die App prüft nicht, mit welchem Server sie spricht",
        "Die App akzeptiert eine sichere Verbindung zu jedem beliebigen Websitenamen, sodass ein Angreifer mit irgendeinem gültigen Zertifikat ihren Datenverkehr abfangen kann.",
        "Lösche den eigenen `HostnameVerifier`, der immer true zurückgibt, und nutze den Standard."),
    "webview-ignores-ssl-errors": ("Eingebettete Webseiten ignorieren Sicherheitswarnungen",
        "Wenn eine Seite in der App ein fehlerhaftes oder gefälschtes Zertifikat hat, lädt die App sie trotzdem, sodass die Seite und alles, was dort eingegeben wird, abgefangen werden kann.",
        "Rufe in `onReceivedSslError` `handler.cancel()` statt `handler.proceed()` auf."),
    "weak-tls-version": ("Die App erlaubt veraltete Verschlüsselung für Verbindungen",
        "Alte Versionen der Verbindungssicherheit haben bekannte Schwächen, mit denen Angreifer den Datenverkehr lesen können.",
        "Erlaube nur TLS 1.2 und 1.3; entferne Verweise auf SSLv3, TLS 1.0 und TLS 1.1."),
    "cleartext-traffic": ("Die App darf Daten unverschlüsselt senden",
        "Die App darf einfache http://-Verbindungen nutzen, die jeder im selben Netzwerk lesen oder ändern kann.",
        "Setze `android:usesCleartextTraffic=\"false\"` und stelle jede Serveradresse auf https:// um."),
    "nsc-cleartext": ("Für manche Server sind unverschlüsselte Verbindungen erlaubt",
        "Die Netzwerkeinstellungen der App erlauben einfachen http://-Verkehr, den andere im Netzwerk lesen können.",
        "Setze in der Network Security Config `cleartextTrafficPermitted=\"false\"` und nutze https://."),
    "nsc-user-certs": ("Die App vertraut Zertifikaten, die der Nutzer installiert",
        "Wer ein Zertifikat auf dem Handy installieren kann, kann den sicheren Datenverkehr der App lesen.",
        "Entferne `<certificates src=\"user\"/>` aus der Release-Network-Security-Config (nur in `<debug-overrides>` behalten)."),
    "webview-javascript-enabled": ("Eingebettete Webseiten dürfen Skripte ausführen",
        "Das wird oft gebraucht, aber wenn die App Seiten zeigt, die sie nicht vollständig kontrolliert, könnte eine bösartige Seite Code in der App ausführen.",
        "Aktiviere JavaScript nur für Seiten, die du kontrollierst, und lade sie über https://."),
    "webview-javascript-interface": ("Webseiten können den eigenen Code der App aufrufen",
        "Jede in dieser WebView geladene Seite kann Funktionen der App aufrufen, sodass eine bösartige Seite an App-Daten oder -Funktionen käme.",
        "Füge die JavaScript-Schnittstelle nur für vertrauenswürdige https://-Seiten hinzu und gib so wenige Methoden wie möglich frei."),
    "webview-file-access": ("Eingebettete Webseiten können Dateien auf dem Handy lesen",
        "Eine Seite in der WebView kann möglicherweise die privaten Dateien der App lesen und anderswohin senden.",
        "Rufe `setAllowFileAccess(false)` auf und vermeide die Einstellungen für den Zugriff über Datei-URLs."),
    "weak-hash": ("Die App nutzt ein veraltetes Prüfsummenverfahren",
        "MD5 und SHA-1 lassen sich fälschen, sie dürfen also weder Passwörter schützen noch Downloads prüfen.",
        "Nutze SHA-256 für Prüfungen und ein Passwort-Hashverfahren wie Argon2 oder PBKDF2 für Passwörter."),
    "weak-cipher": ("Die App nutzt schwache Verschlüsselung",
        "Alte oder falsch eingestellte Verschlüsselung (wie DES oder der ECB-Modus) lässt sich knacken und gibt die Daten preis.",
        "Nutze AES im GCM-Modus mit einem zufälligen IV für jede Nachricht."),
    "hardcoded-crypto-key-or-iv": ("Ein Verschlüsselungsschlüssel steht fest in der App",
        "Jeder, der die App herunterlädt, kann diesen Schlüssel auslesen und die damit geschützten Daten entschlüsseln.",
        "Erzeuge Schlüssel zur Laufzeit und bewahre sie im Android Keystore auf; schreibe nie Schlüssel in den Code."),
    "secret": ("Ein Passwort oder API-Schlüssel steht fest in der App",
        "Jeder, der die App herunterlädt, kann dieses Geheimnis auslesen und nutzen – etwa um auf deine Kosten Rechnungen zu verursachen oder an die Daten deiner Nutzer zu kommen.",
        "Sperre und ersetze diesen Schlüssel jetzt und verlege ihn auf deinen Server; die App sollte kurzlebige Token von deinem Backend holen, statt den Schlüssel selbst zu enthalten."),
    "world-readable-file": ("Andere Apps können die Dateien der App lesen",
        "Dateien werden so gespeichert, dass jede App auf dem Handy sie lesen oder überschreiben kann.",
        "Nutze `MODE_PRIVATE` beim Anlegen von Dateien und Shared Preferences."),
    "external-storage": ("Die App nutzt den gemeinsamen Speicher des Handys",
        "Dateien im gemeinsamen Speicher können von anderen Apps gelesen werden, sie dürfen also keine persönlichen Daten enthalten.",
        "Bewahre persönliche Daten im privaten Speicher der App auf (`getFilesDir()`)."),
    "sensitive-data-logged": ("Private Informationen landen möglicherweise in den Logs",
        "Logs lassen sich über Debugging-Tools und Absturzberichte lesen, wodurch Passwörter oder Token offengelegt werden könnten.",
        "Entferne diese Log-Zeilen oder lass das Logging in Release-Builds weg."),
    "allow-backup": ("App-Daten können vom Handy kopiert werden",
        "Ein Backup-Tool kann die Daten der App, auch gespeicherte Anmeldungen, auf ein anderes Gerät kopieren.",
        "Setze `android:allowBackup=\"false\"` oder schließe private Dateien mit Backup-Regeln aus."),
    "sql-string-concatenation": ("Eine Datenbankabfrage wird aus rohem Text gebaut",
        "Wenn ein Teil dieses Texts von einem Nutzer oder Server kommt, könnte er die Abfrage verändern und Daten lesen oder löschen, die tabu sind.",
        "Nutze Abfrageparameter (`?`-Platzhalter mit Selection-Argumenten), statt Strings zusammenzufügen."),
    "zip-path-traversal": ("Das Entpacken einer ZIP-Datei kann die eigenen Dateien der App überschreiben",
        "Eine präparierte ZIP-Datei kann Namen wie ../../ enthalten, die Dateien außerhalb des Zielordners schreiben und so App-Code oder Daten ersetzen.",
        "Prüfe vor dem Schreiben jedes Eintrags, dass sein aufgelöster Pfad im Zielordner bleibt."),
    "runtime-exec": ("Die App führt Befehle auf dem Handy aus",
        "Wenn ein Teil des Befehls von außerhalb der App kommt, könnte ein Angreifer eigene Befehle ausführen.",
        "Vermeide Shell-Befehle; wenn es nötig ist, baue den Befehl nie aus Eingaben von außen."),
    "dynamic-code-loading": ("Die App lädt während der Laufzeit zusätzlichen Code",
        "Zur Laufzeit geladener Code wird vom Play Store nicht geprüft, und wenn seine Quelle verändert werden kann, kann ein Angreifer eigenen Code in der App ausführen.",
        "Liefere allen Code mit der App aus oder prüfe die Signatur jedes geladenen Codes."),
    "string-compared-with-equals-sign": ("Text wird falsch verglichen",
        "Ein Vergleich von Text mit == prüft, ob es dasselbe Objekt ist, nicht dieselben Wörter, sodass Prüfungen zufällig fehlschlagen können.",
        "Nutze `.equals()` (oder `TextUtils.equals()`), um Strings zu vergleichen."),
    "handler-without-looper": ("Hintergrundarbeit wird auf veraltete Weise geplant",
        "Dieses alte Muster kann Arbeit im falschen Thread ausführen und seltene Abstürze oder Hänger verursachen.",
        "Gib einen Looper ausdrücklich an, zum Beispiel `new Handler(Looper.getMainLooper())`."),
    "catch-null-pointer": ("Ein Absturz wird versteckt statt behoben",
        "Der Code fängt einen Absturz wegen eines fehlenden Werts ab, statt den fehlenden Wert zu prüfen, und versteckt so echte Fehler.",
        "Prüfe vor der Verwendung auf null und entferne das `catch (NullPointerException)`."),
    "empty-catch-block": ("Fehler werden stillschweigend ignoriert",
        "Wenn hier etwas schiefgeht, macht die App weiter, als wäre nichts passiert, was Fehler schwer auffindbar macht.",
        "Protokolliere den Fehler oder behandle ihn so, dass der Nutzer sieht, was schiefgelaufen ist."),
    "print-stack-trace": ("Fehlerdetails werden in die Logs geschrieben",
        "Rohe Fehlerdetails in Logs können verraten, wie die App funktioniert, und gehen in Release-Builds verloren.",
        "Ersetze `printStackTrace()` durch richtiges Logging oder einen Crash-Reporter."),
    "system-exit": ("Die App beendet sich abrupt selbst",
        "Das Beenden des App-Prozesses überspringt das normale Aufräumen und kann Nutzerdaten verlieren.",
        "Schließe den Bildschirm mit `finish()` statt mit `System.exit()`."),
    "apk-signature-invalid": ("Die Signatur der App fehlt oder ist defekt",
        "Android kann nicht bestätigen, wer diese Datei gebaut hat oder dass sie danach niemand verändert hat, und Handys verweigern die Installation.",
        "Baue das Release mit „Generate Signed App Bundle / APK“ in Android Studio und deinem Release-Schlüssel neu."),
    "apk-signature-v1-only": ("Die App nutzt nur das alte Signaturverfahren",
        "Die alte v1-Signatur deckt nicht die ganze Datei ab, sodass ein Angreifer auf älteren Handys Code einschleusen kann, ohne die Signatur zu brechen (die Janus-Lücke, CVE-2017-13156).",
        "Aktiviere die v2- und v3-Signatur (Standard in aktuellen Android-Build-Tools) und baue neu."),
    "apk-debug-certificate": ("Die App ist mit einem Entwickler-Testschlüssel signiert",
        "Der Debug-Schlüssel wird automatisch erzeugt, hat das bekannte Passwort „android“, und Google Play lehnt damit signierte Apps ab. Updates mit deinem echten Schlüssel lassen sich nicht über diesen Build installieren.",
        "Erstelle einen Release-Schlüssel und signiere den Release-Build damit."),
    "apk-weak-signing-key": ("Der Signaturschlüssel der App ist zu schwach",
        "Ein kurzer oder veralteter Schlüssel lässt sich leichter fälschen, sodass jemand gefälschte Updates veröffentlichen könnte.",
        "Nutze einen RSA-Schlüssel mit mindestens 2048 Bit (oder EC 256). Mit der Schlüsselrotation von Google Play lässt sich eine bestehende App auf einen neuen Schlüssel umstellen."),
    "debuggable": ("Die App wurde im Debug-Modus veröffentlicht",
        "Jeder mit einem USB-Kabel kann den Speicher und die privaten Daten der App auf dem Handy untersuchen.",
        "Entferne `android:debuggable=\"true\"` und baue die Release-Version der App."),
    "old-target-sdk": ("Die App ist für eine alte Android-Version gebaut",
        "Wer eine alte Android-Version anvisiert, verzichtet auf neuere Datenschutz- und Sicherheitsfunktionen.",
        "Erhöhe `targetSdkVersion` auf die Version, die der Play Store derzeit verlangt."),
    "exported-service": ("Andere Apps können einen Hintergrunddienst der App starten",
        "Jede App auf dem Handy kann diesen Dienst ohne Berechtigung auslösen.",
        "Setze `android:exported=\"false\"` oder schütze ihn mit einer Berechtigung."),
    "exported-receiver": ("Andere Apps können dieser App Nachrichten senden",
        "Jede App auf dem Handy kann dieser App Ereignisse senden, auf die sie reagiert, ohne zu prüfen, wer sie geschickt hat.",
        "Setze `android:exported=\"false\"` oder schütze ihn mit einer Berechtigung."),
    "exported-provider": ("Andere Apps können die geteilten Daten der App lesen",
        "Jede App auf dem Handy kann diesen Datenspeicher ohne Berechtigung abfragen.",
        "Setze `android:exported=\"false\"` oder schütze ihn mit Lese- und Schreibberechtigungen."),
    "web-innerhtml-assignment": ("Text von außen wird als HTML in die Seite eingefügt",
        "Wenn ein Teil dieses Texts von einem Besucher oder einer anderen Website stammt, kann ein Angreifer damit sein eigenes Skript auf deiner Seite ausführen und Anmeldungen stehlen (Cross-Site-Scripting).",
        "Nutze `textContent` für reinen Text oder bereinige das HTML vorher mit einer Bibliothek wie DOMPurify."),
    "web-document-write": ("Die Seite schreibt HTML mit document.write",
        "HTML, das aus Variablen gebaut wird, kann einem Angreifer erlauben, sein eigenes Skript einzuschleusen.",
        "Ersetze `document.write` durch DOM-Methoden wie `textContent` oder `appendChild`."),
    "web-dangerously-set-inner-html": ("React fügt rohes HTML in die Seite ein",
        "`dangerouslySetInnerHTML` mit Daten von Nutzern oder einer API kann das Skript eines Angreifers ausführen.",
        "Gib die Daten als normalen JSX-Text aus oder bereinige sie vor dem Einfügen mit DOMPurify."),
    "web-eval": ("Die Website führt Text als Code aus",
        "Wenn ein Besucher den Text beeinflussen kann (zum Beispiel über die URL), kann ein Angreifer beliebigen Code in den Browsern deiner Nutzer ausführen.",
        "Entferne `eval` / `new Function`; lies Daten mit `JSON.parse` ein oder nutze eine sichere Bibliothek für Ausdrücke."),
    "web-token-in-localstorage": ("Anmelde-Token liegen dort, wo jedes Skript sie lesen kann",
        "Alles im localStorage kann von jedem Skript auf der Seite gelesen werden, ein einziges eingeschleustes Skript reicht also, um die Sitzung jedes Nutzers zu stehlen.",
        "Bewahre Sitzungs-Token in `HttpOnly`- und `Secure`-Cookies auf, die dein Server setzt."),
    "web-postmessage-no-origin-check": ("Die Seite vertraut Nachrichten von jeder Website",
        "Jede Website, die deine Seite öffnet oder einbettet, kann ihr Nachrichten senden, und die Seite reagiert darauf, ohne zu prüfen, wer sie geschickt hat.",
        "Brich am Anfang des Message-Handlers ab, wenn `event.origin` nicht eine deiner eigenen Domains ist."),
    "web-postmessage-wildcard": ("Die Seite sendet Daten an jede Website",
        "Nachrichten an '*' zu senden bedeutet, dass eine bösartige Seite, die deine einbettet, sie lesen kann.",
        "Gib als zweites Argument von `postMessage` den genauen Origin deiner übergeordneten Website statt '*' an."),
    "web-insecure-http-request": ("Die Website ruft einen Server ohne Verschlüsselung auf",
        "Anfragen an http://-Adressen kann jeder im selben Netzwerk lesen und ändern, auch Passwörter und Token.",
        "Stelle die Adresse auf https:// um und sorg dafür, dass der Server es unterstützt."),
    "web-sensitive-console-log": ("Ein Token oder Passwort wird in die Browserkonsole geschrieben",
        "Browser-Erweiterungen, Bildschirmfreigaben und Support-Screenshots können zeigen, was dort steht.",
        "Entferne die `console.log`-Zeile oder protokolliere nur, dass die Aktion geklappt hat."),
    "web-secret": ("Ein geheimer Schlüssel ist im Code der Website sichtbar",
        "Alles, was eine Website an den Browser sendet, kann jeder lesen, dieser Schlüssel ist also öffentlich. Angreifer können damit Rechnungen verursachen oder an deine Daten kommen.",
        "Sperre und ersetze den Schlüssel jetzt und verlege den Aufruf, der ihn braucht, in eine serverseitige Funktion (zum Beispiel eine API-Route oder Edge-Funktion). Nur Schlüssel, die öffentlich sein sollen, gehören in den Browser."),
    "supabase-service-role-key": ("Der Supabase-Admin-Schlüssel steht im Code der Website",
        "Der service_role-Schlüssel umgeht jede Row Level Security, sodass jeder jede Zeile deiner Datenbank lesen, ändern oder löschen kann.",
        "Erneuere den service_role-Schlüssel jetzt im Supabase-Dashboard, nutze im Browser den anon-Schlüssel und schütze Tabellen mit Row-Level-Security-Richtlinien."),
    "web-no-https": ("Die Website nutzt kein HTTPS",
        "Alles, was Besucher senden, auch Passwörter, wird unverschlüsselt übertragen und kann in öffentlichen WLANs gelesen oder verändert werden.",
        "Schalte HTTPS mit einem kostenlosen Zertifikat ein (die meisten Hoster machen das automatisch) und leite http:// auf https:// um."),
    "web-no-https-redirect": ("Die http://-Adresse leitet nicht auf HTTPS um",
        "Besucher, die die Adresse ohne https:// eintippen, bleiben auf einer unverschlüsselten Verbindung.",
        "Leite jede http://-Anfrage auf die https://-Adresse um (Status 301 oder 308)."),
    "web-missing-hsts": ("Browsern wird nicht gesagt, immer HTTPS zu nutzen",
        "Ohne den HSTS-Header kann ein Angreifer im Netzwerk einen Besucher auf einfaches http:// herunterstufen.",
        "Sende `Strict-Transport-Security: max-age=31536000; includeSubDomains` bei HTTPS-Antworten."),
    "web-missing-csp": ("Keine Content Security Policy",
        "Eine Content Security Policy begrenzt, welche Skripte laufen dürfen, und stoppt so die meisten eingeschleusten Skripte. Diese Website hat keine.",
        "Füge einen `Content-Security-Policy`-Header hinzu, beginnend mit `default-src 'self'`, und erlaube nur die Domains, die du nutzt."),
    "web-missing-frame-protection": ("Andere Websites können diese Seite unsichtbar einbetten",
        "Ein Angreifer kann deine Website in einem unsichtbaren Frame laden und Besucher dazu bringen, Schaltflächen anzuklicken (Clickjacking).",
        "Sende `Content-Security-Policy: frame-ancestors 'self'` (oder `X-Frame-Options: DENY`)."),
    "web-missing-nosniff": ("Browser dürfen Dateitypen raten",
        "Ohne den nosniff-Header kann ein Browser eine hochgeladene Datei als Skript behandeln.",
        "Sende bei jeder Antwort `X-Content-Type-Options: nosniff`."),
    "web-cookie-insecure": ("Einem Cookie fehlen die Sicherheitsmerkmale",
        "Cookies ohne Secure, HttpOnly und SameSite können von Skripten gestohlen, unverschlüsselt gesendet oder von anderen Websites missbraucht werden.",
        "Setze Cookies mit `Secure; HttpOnly; SameSite=Lax` (oder `Strict`)."),
    "web-server-version-disclosure": ("Der Server verrät, welche Software er nutzt",
        "Versionsangaben helfen Angreifern, bekannte Schwächen genau dieser Software nachzuschlagen.",
        "Entferne `X-Powered-By` und verstecke Versionsnummern im `Server`-Header."),
    "web-exposed-env-file": ("Die .env-Datei der Website kann heruntergeladen werden",
        "Diese Datei enthält meist Datenbankpasswörter und API-Schlüssel, und jeder kann sie herunterladen.",
        "Lösche sie aus dem öffentlichen Ordner, sperre Punktdateien auf dem Server und erneuere jeden Schlüssel, den sie enthielt."),
    "web-exposed-git": ("Der .git-Ordner der Website kann heruntergeladen werden",
        "Jeder kann die komplette Quellcode-Historie herunterladen, oft samt alter Passwörter und Schlüssel.",
        "Sperre den Zugriff auf `/.git/` auf dem Server (oder veröffentliche ohne ihn) und erneuere jedes Geheimnis, das je committet wurde."),
    "web-source-map-exposed": ("Der ursprüngliche Quellcode der Website ist öffentlich",
        "Source-Map-Dateien stellen deinen ursprünglichen, lesbaren Code wieder her und machen es leicht, Schwächen und versteckte Endpunkte zu finden.",
        "Lade keine `.map`-Dateien mehr in die Produktion hoch oder beschränke sie auf deinen Fehler-Tracking-Dienst."),
}

STRUCTURE = {
    "A method is too long to follow easily": "Eine Methode ist zu lang, um ihr leicht zu folgen",
    "Long methods are hard to read and test, so bugs hide in them and changes break things.":
        "Lange Methoden sind schwer zu lesen und zu testen, sodass sich Fehler darin verstecken und Änderungen etwas kaputt machen.",
    "more than 75 lines": "mehr als 75 Zeilen",
    "A method takes too many parameters": "Eine Methode hat zu viele Parameter",
    "Calls are easy to get wrong (arguments in the wrong order) and the method is doing too much.":
        "Aufrufe geraten leicht falsch (Argumente in falscher Reihenfolge), und die Methode macht zu viel.",
    "more than 7 parameters": "mehr als 7 Parameter",
}

# Messages from the server that appear on the page as they are (errors, notes).
SERVER = {
    "Please sign in with your email to scan. It's free and takes a minute.":
        "Bitte melde dich mit deiner E-Mail-Adresse an, um zu scannen. Es ist kostenlos und dauert eine Minute.",
    "Scan refused: you must confirm you own this app or have permission to test it (i_am_authorized=true).":
        "Scan abgelehnt: Du musst bestätigen, dass dir diese App gehört oder du sie testen darfst.",
    "The deep engine is not installed on this server; choose Fast · jadx.":
        "Die gründliche Engine ist auf diesem Server nicht installiert; wähle Schnell · jadx.",
    "Please upload an Android app file ending in .apk.": "Bitte lade eine Android-App-Datei mit der Endung .apk hoch.",
    "A deep scan is already running and it needs most of the server's memory. Try again later, or choose Fast · jadx (same issues, about 1 minute).":
        "Ein gründlicher Scan läuft bereits und braucht den Großteil des Server-Speichers. Versuch es später erneut oder wähle Schnell · jadx (dieselben Probleme, etwa 1 Minute).",
    "The scanner is busy with other apps right now. Try again in a minute.":
        "Der Scanner ist gerade mit anderen Apps beschäftigt. Versuch es in einer Minute erneut.",
    "This file couldn't be opened as an Android app. Make sure it's a complete, unencrypted .apk file.":
        "Diese Datei ließ sich nicht als Android-App öffnen. Stelle sicher, dass es eine vollständige, unverschlüsselte .apk-Datei ist.",
    "Something went wrong while scanning this app. Please try again.":
        "Beim Scannen dieser App ist etwas schiefgelaufen. Bitte versuch es erneut.",
    "The scan stopped before it finished. Please try again.": "Der Scan wurde vor dem Ende gestoppt. Bitte versuch es erneut.",
    "Please sign in.": "Bitte melde dich an.",
    "You cancelled this scan.": "Du hast diesen Scan abgebrochen.",
    "Scan refused: you must confirm you own this website or have permission to test it (i_am_authorized=true).":
        "Scan abgelehnt: Du musst bestätigen, dass dir diese Website gehört oder du sie testen darfst.",
    "The scanner is busy right now. Try again in a minute.": "Der Scanner ist gerade beschäftigt. Versuch es in einer Minute erneut.",
    "Something went wrong while scanning this website. Please try again.":
        "Beim Scannen dieser Website ist etwas schiefgelaufen. Bitte versuch es erneut.",
    "The website scan stopped before it finished.": "Der Website-Scan wurde vor dem Ende gestoppt.",
    "Scan refused: you must confirm you own this code or have permission to change it.":
        "Scan abgelehnt: Du musst bestätigen, dass dir dieser Code gehört oder du ihn ändern darfst.",
    "Please upload your project as a .zip file.": "Bitte lade dein Projekt als .zip-Datei hoch.",
    "Something went wrong while scanning this project. Please try again.":
        "Beim Scannen dieses Projekts ist etwas schiefgelaufen. Bitte versuch es erneut.",
    "The source scan stopped before it finished.": "Der Quellcode-Scan wurde vor dem Ende gestoppt.",
    "The fixes are not ready yet.": "Die Korrekturen sind noch nicht fertig.",
    "Please sign in to open this report.": "Bitte melde dich an, um diesen Bericht zu öffnen.",
    "No such report.": "Diesen Bericht gibt es nicht.",
    "This file isn't a valid .apk or .zip (both are ZIP archives).": "Diese Datei ist keine gültige .apk oder .zip (beides sind ZIP-Archive).",
    "This report has expired. Please scan again.": "Dieser Bericht ist abgelaufen. Bitte scanne erneut.",
    "This report has not been paid for.": "Dieser Bericht wurde nicht bezahlt.",
    "Secure & Auto-Fix works on your source code: upload it on the \"Fix my code\" tab.":
        "Secure & Auto-Fix arbeitet mit deinem Quellcode: Lade ihn im Tab „Meinen Code beheben“ hoch.",
    "Deep Architecture Audit works on your source code: upload it on the \"Fix my code\" tab.":
        "Das Deep Architecture Audit arbeitet mit deinem Quellcode: Lade ihn im Tab „Meinen Code beheben“ hoch.",
    "This plan is for app and website scans.": "Dieser Tarif ist für App- und Website-Scans.",
    "Demo payments are switched off on this server.": "Demo-Zahlungen sind auf diesem Server ausgeschaltet.",
    "This order was cancelled. Start a new checkout from the report.":
        "Diese Bestellung wurde storniert. Starte eine neue Bezahlung über den Bericht.",
    "Please enter a valid email address.": "Bitte gib eine gültige E-Mail-Adresse ein.",
    "Please use your own email address, not a temporary inbox.":
        "Bitte nutze deine eigene E-Mail-Adresse, kein Wegwerf-Postfach.",
    "Too many codes were requested for this email. Try again in an hour.":
        "Für diese E-Mail-Adresse wurden zu viele Codes angefordert. Versuch es in einer Stunde erneut.",
    "This code has expired. Ask for a new one.": "Dieser Code ist abgelaufen. Fordere einen neuen an.",
    "Too many wrong codes. Ask for a new one.": "Zu viele falsche Codes. Fordere einen neuen an.",
    "Your email address isn't confirmed yet. Use the link in the email Supabase sent you.":
        "Deine E-Mail-Adresse ist noch nicht bestätigt. Nutze den Link in der E-Mail, die Supabase dir geschickt hat.",
    "Sign-in failed. Please try again.": "Anmeldung fehlgeschlagen. Bitte versuch es erneut.",
    "Your sign-in has expired. Please sign in again.": "Deine Anmeldung ist abgelaufen. Bitte melde dich erneut an.",
    "Supabase sign-in is not reachable right now. Please try again.":
        "Die Supabase-Anmeldung ist gerade nicht erreichbar. Bitte versuch es erneut.",
    "Too many new accounts were created from this network today. Sign in with an existing account, or try again tomorrow.":
        "Aus diesem Netzwerk wurden heute zu viele neue Konten angelegt. Melde dich mit einem bestehenden Konto an oder versuch es morgen erneut.",
    "We couldn't send the email right now. Please try again in a minute.":
        "Wir konnten die E-Mail gerade nicht senden. Bitte versuch es in einer Minute erneut.",
    "Please enter the website address.": "Bitte gib die Website-Adresse ein.",
    "Only http:// and https:// website addresses can be scanned.": "Nur Website-Adressen mit http:// und https:// können gescannt werden.",
    "Please remove the username and password from the address.": "Bitte entferne Benutzername und Passwort aus der Adresse.",
    "Scanning localhost is switched off on this server.": "Das Scannen von localhost ist auf diesem Server ausgeschaltet.",
    "This address points into a private network, which can't be scanned.":
        "Diese Adresse zeigt in ein privates Netzwerk, das nicht gescannt werden kann.",
    "The website redirects too many times.": "Die Website leitet zu oft um.",
    "The website did not respond. Check that it is online.": "Die Website hat nicht geantwortet. Prüfe, ob sie online ist.",
    "This site's JavaScript was too large to analyse together with its source maps, so the check for public source maps was skipped. Everything else was checked.":
        "Das JavaScript dieser Website war zu groß, um es zusammen mit seinen Source Maps zu analysieren, deshalb wurde die Prüfung auf öffentliche Source Maps übersprungen. Alles andere wurde geprüft.",
    "No JavaScript was captured from this page, so only the server settings were checked.":
        "Von dieser Seite wurde kein JavaScript erfasst, daher wurden nur die Server-Einstellungen geprüft.",
    "This file is not a valid .zip archive.": "Diese Datei ist kein gültiges .zip-Archiv.",
    "The zip is too large once unpacked. Leave out build folders and try again.":
        "Die ZIP-Datei ist entpackt zu groß. Lass Build-Ordner weg und versuch es erneut.",
    "No supported source code found. VibeGuard checks Android projects (.java, .kt, AndroidManifest.xml) and web projects (.js, .jsx, .ts, .tsx).":
        "Kein unterstützter Quellcode gefunden. VibeGuard prüft Android-Projekte (.java, .kt, AndroidManifest.xml) und Webprojekte (.js, .jsx, .ts, .tsx).",
    "This is a Flutter app: most of its logic is compiled Dart code, which this scan cannot read, so only the Android parts were checked.":
        "Dies ist eine Flutter-App: Der Großteil ihrer Logik ist kompilierter Dart-Code, den dieser Scan nicht lesen kann, daher wurden nur die Android-Teile geprüft.",
}

# Words used inside composed sentences; also the values captured by PATTERNS.
WORDS = {
    "app": "App", "website": "Website", "code": "Code",
    "VibeGuard deep engine": "Gründliche VibeGuard-Engine", "Scanning": "Scan läuft",
    "Leaked secret": "Geleaktes Geheimnis", "Security": "Sicherheit", "Logic bug": "Logikfehler",
    "Likely bug": "Wahrscheinlicher Fehler", "Code quality": "Code-Qualität",
    "the deep engine is not installed here": "die gründliche Engine hier nicht installiert ist",
    "the deep engine ran out of memory analysing this site's JavaScript":
        "der gründlichen Engine beim Analysieren des JavaScripts dieser Website der Speicher ausging",
    "the deep engine took too long to analyse this site's JavaScript":
        "die gründliche Engine zu lange für das JavaScript dieser Website brauchte",
    "high": "hoch", "medium": "mittel", "low": "niedrig",
    "critical": "kritisch", "warning": "Warnung", "smell": "Smell",
    "AI code review (not verified)": "KI-Code-Prüfung (nicht bestätigt)",
    "AI review: probably a false alarm here:": "KI-Prüfung: hier wahrscheinlich ein Fehlalarm:",
    "AI review: some of these places are probably false alarms:": "KI-Prüfung: einige dieser Stellen sind wahrscheinlich Fehlalarme:",
}
TERMS = [  # applied, in order, to a captured value that is not a known sentence
    ("JavaScript/TypeScript files", "JavaScript/TypeScript-Dateien"), ("JavaScript/TypeScript file", "JavaScript/TypeScript-Datei"),
    ("Java files", "Java-Dateien"), ("Java file", "Java-Datei"), ("Kotlin files", "Kotlin-Dateien"),
    ("Kotlin file", "Kotlin-Datei"), ("no code files", "keine Code-Dateien"), (" and ", " und "),
    ("the fast engine (jadx)", "der schnellen Engine (jadx)"),
    ("the VibeGuard deep engine", "der gründlichen VibeGuard-Engine"),
    ("VibeGuard's direct fetch", "dem direkten Abruf von VibeGuard"),
    (" methods checked", " Methoden geprüft"), ("completed with the fast engine", "mit der schnellen Engine vervollständigt"),
    ("All ", "Alle "), (" of ", " von "), (" · took ", " · Dauer "), ("explained by ", "erklärt von "),
    ("more than 75 lines", "mehr als 75 Zeilen"), ("more than 7 parameters", "mehr als 7 Parameter"),
]

N = r"(\d[\d,]*)"
PATTERNS = [
    # ---- account, limits, sign-in
    (rf"Free scans left today: {N} of {N}\. Scanning the same app again is free\.",
     "Heute noch $1 von $2 kostenlosen Scans. Dieselbe App erneut zu scannen ist kostenlos."),
    (rf"You have used today's {N} free scans\. They reset in about {N} hours?; apps you already scanned can still be opened\.",
     "Du hast die $1 kostenlosen Scans von heute verbraucht. Sie werden in etwa $2 Stunden zurückgesetzt; bereits gescannte Apps kannst du weiterhin öffnen."),
    (rf"You have used your {N} free scans for today\. They reset in about {N} hours?\. Results you already scanned stay available\.",
     "Du hast deine $1 kostenlosen Scans für heute verbraucht. Sie werden in etwa $2 Stunden zurückgesetzt. Bereits gescannte Ergebnisse bleiben verfügbar."),
    (rf"This network has used its {N} free scans for today\. They reset in about {N} hours?\. Results you already scanned stay available\.",
     "Dieses Netzwerk hat seine $1 kostenlosen Scans für heute verbraucht. Sie werden in etwa $2 Stunden zurückgesetzt. Bereits gescannte Ergebnisse bleiben verfügbar."),
    (r"Signed in as (.+)", "Angemeldet als $1"),
    (r"Code created for (.+)\. It expires in 10 minutes\.", "Code für $1 erstellt. Er läuft in 10 Minuten ab."),
    (r"We sent a code to (.+)\. It expires in 10 minutes; check your spam folder if it doesn't arrive\.",
     "Wir haben einen Code an $1 gesendet. Er läuft in 10 Minuten ab; schau in deinen Spam-Ordner, falls er nicht ankommt."),
    (r"We sent a sign-in link to (.+)\. Open it in this browser to continue\.",
     "Wir haben einen Anmeldelink an $1 gesendet. Öffne ihn in diesem Browser, um fortzufahren."),
    (rf"A code was just sent\. You can ask for a new one in {N} seconds\.",
     "Gerade wurde ein Code gesendet. Einen neuen kannst du in $1 Sekunden anfordern."),
    (rf"That code is not right\. {N} tr(?:ies|y) left\.", "Dieser Code stimmt nicht. Noch $1 Versuch(e)."),
    (r"You're signed in · unlimited scans", "Du bist angemeldet · unbegrenzte Scans"),
    (rf"You're signed in · {N} of {N} free scans left today", "Du bist angemeldet · heute noch $1 von $2 kostenlosen Scans"),
    (r"You're signed in", "Du bist angemeldet"),
    (rf"Free: {N} scans a day · no card needed · sign in with Google",
     "Kostenlos: $1 Scans pro Tag · keine Karte nötig · Anmeldung mit Google"),
    # ---- uploads and progress
    (rf"This zip is {N} MB\. The limit is 50 MB; leave out build folders\.",
     "Diese ZIP-Datei hat $1 MB. Die Grenze liegt bei 50 MB; lass Build-Ordner weg."),
    (r"([\d.]+) MB · click to choose a different file", "$1 MB · klicke, um eine andere Datei zu wählen"),
    (rf"This file is {N} MB\. The limit is {N} MB\.", "Diese Datei hat $1 MB. Die Grenze liegt bei $2 MB."),
    (rf"The file is too big\. The limit is {N} MB\.", "Die Datei ist zu groß. Die Grenze liegt bei $1 MB."),
    (rf"{N} seconds so far", "bisher $1 Sekunden"),
    (rf"{N} min {N} s so far · a deep scan takes about 13 minutes", "bisher $1 Min. $2 s · ein gründlicher Scan dauert etwa 13 Minuten"),
    (rf"{N} s so far · a deep scan takes about 13 minutes", "bisher $1 s · ein gründlicher Scan dauert etwa 13 Minuten"),
    (rf"{N} min {N} s so far", "bisher $1 Min. $2 s"),
    (rf"{N} s so far", "bisher $1 s"),
    (r"(VibeGuard deep engine|Scanning): (.+)", "$1: $2"),
    (rf"The server returned an error \({N}\)\.", "Der Server hat einen Fehler gemeldet ($1)."),
    (rf"Your deep scan of (.+) is still running \(started {N} minutes? ago\)\. It will show here when it's done\.",
     "Dein gründlicher Scan von $1 läuft noch (gestartet vor $2 Min.). Er erscheint hier, sobald er fertig ist."),
    (rf"Your scan of (.+) is still running \(started {N} minutes? ago\)\. It will show here when it's done\.",
     "Dein Scan von $1 läuft noch (gestartet vor $2 Min.). Er erscheint hier, sobald er fertig ist."),
    # ---- website verification and capture
    (r"We didn't find the verification tag on (\S+) or the file at (\S+)\. Nothing was scanned and no free scan was used\.",
     "Wir haben weder das Bestätigungs-Tag auf $1 noch die Datei unter $2 gefunden. Es wurde nichts gescannt und kein kostenloser Scan verbraucht."),
    (r"Couldn't verify that you control this site\. Add (.+) to your homepage, or put the token (\S+) in a file at (\S+), and try again\.",
     "Wir konnten nicht bestätigen, dass du diese Website kontrollierst. Füge $1 auf deiner Startseite ein oder lege den Token $2 in einer Datei unter $3 ab und versuch es erneut."),
    (r"The website (.+) could not be found\. Check the address\.", "Die Website $1 wurde nicht gefunden. Prüfe die Adresse."),
    (rf"Captured with VibeGuard's direct fetch because (.+)\. The {N} scripts this page links to were checked; scripts it loads later while running were not\.",
     "Mit dem direkten Abruf von VibeGuard erfasst, weil $1. Die $2 Skripte, auf die diese Seite verweist, wurden geprüft; Skripte, die sie später beim Ausführen lädt, nicht."),
    # ---- reports
    (r"Example report · F-Droid, an open-source app store", "Beispielbericht · F-Droid, ein Open-Source-App-Store"),
    (r"Free source scan · (.+)", "Kostenloser Quellcode-Scan · $1"),
    (r"Free scan · (.+)", "Kostenloser Scan · $1"),
    (r"Website scan · (.+)", "Website-Scan · $1"),
    (r"We found 1 problem in your code", "Wir haben 1 Problem in deinem Code gefunden"),
    (rf"We found {N} problems in your code", "Wir haben $1 Probleme in deinem Code gefunden"),
    (r"We found 1 problem in your app", "Wir haben 1 Problem in deiner App gefunden"),
    (rf"We found {N} problems in your app", "Wir haben $1 Probleme in deiner App gefunden"),
    (r"We found 1 problem in your website", "Wir haben 1 Problem auf deiner Website gefunden"),
    (rf"We found {N} problems in your website", "Wir haben $1 Probleme auf deiner Website gefunden"),
    (r"No problems found in your app", "In deiner App wurden keine Probleme gefunden"),
    (r"No problems found in your website", "Auf deiner Website wurden keine Probleme gefunden"),
    (r"Scan another (app|website)", "Eine andere $1 scannen"),
    (r"Result fingerprint (\w+) · the paid report has these issues and this fingerprint; any the AI judges false alarms are listed separately and not counted",
     "Ergebnis-Fingerabdruck $1 · der bezahlte Bericht hat diese Probleme und diesen Fingerabdruck; was die KI als "
     "Fehlalarm einstuft, wird getrennt aufgeführt und nicht gezählt"),
    (r"Result fingerprint (\w+) · the same app always gives the same issues and fingerprint",
     "Ergebnis-Fingerabdruck $1 · dieselbe App ergibt immer dieselben Probleme und denselben Fingerabdruck"),
    (r"Result fingerprint (\w+) · same app, same result, every time",
     "Ergebnis-Fingerabdruck $1 · gleiche App, gleiches Ergebnis, jedes Mal"),
    (rf"Result fingerprint (\w+) · Checked (.+)\. Not checked: {N} build scripts? \(\.kts\)\.",
     "Ergebnis-Fingerabdruck $1 · Geprüft: $2. Nicht geprüft: $3 Build-Skript(e) (.kts)."),
    (r"Result fingerprint (\w+) · Checked (.+)\.", "Ergebnis-Fingerabdruck $1 · Geprüft: $2."),
    (rf"1 place · (\S+) · (CWE-\d+)", "1 Stelle · $1 · $2"),
    (rf"{N} places · (\S+) · (CWE-\d+)", "$1 Stellen · $2 · $3"),
    (rf"{N} places? in {N} files? · (\S+) · (CWE-\d+)", "$1 Stelle(n) in $2 Datei(en) · $3 · $4"),
    (rf"{N} places? in {N} files?", "$1 Stelle(n) in $2 Datei(en)"),
    (r"(.+?) · (MASVS-\w+|ASVS-\w+) · (CWE-\d+) · found by (.+?) · (\d+) places",
     "$1 · $2 · $3 · gefunden von $4 · $5 Stellen"),
    (r"(.+?) · (MASVS-\w+|ASVS-\w+) · (CWE-\d+) · found by (.+)", "$1 · $2 · $3 · gefunden von $4"),
    (r"(Fix before you release|Fix soon|Clean up when you can) · (\d+)", "$1 · $2"),
    (rf"and {N} more places?", "und $1 weitere Stelle(n)"),
    (rf"Not verified · not counted above · {N}", "Nicht bestätigt · oben nicht mitgezählt · $1"),
    (rf"Not counted above · {N}", "Oben nicht mitgezählt · $1"),
    (rf"{N} matches", "$1 Treffer"),
    (rf"{N} places", "$1 Stellen"),
    (rf"1 issue · {N} places?", "1 Problem · $1 Stelle(n)"),
    (rf"{N} issues · {N} places", "$1 Probleme · $2 Stellen"),
    (rf"Not counted: {N} probable false alarms \(listed below the issues\)",
     "Nicht gezählt: $1 wahrscheinliche Fehlalarme (unter den Problemen aufgeführt)"),
    (r"(.+?) · AI rates it (\w+) · confidence (\w+)(.*)", "$1 · KI-Einschätzung: $2 · Sicherheit: $3$4"),
    (rf"Scanned (.+?) · {N} raw findings · (.+?) · took {N}s", "Gescannt: $1 · $2 Rohbefunde · $3 · Dauer $4 s"),
    (rf"Scanned (.+?) · {N} raw findings · (.+)", "Gescannt: $1 · $2 Rohbefunde · $3"),
    (r"Decompiled with (.+?) · engine ([\d.]+) · severity policy ([\d.]+) \((.+?), CWE\)(.*)",
     "Dekompiliert mit $1 · Engine $2 · Schweregrad-Richtlinie $3 ($4, CWE)$5"),
    (r"Signature: valid · schemes (.+?) · (\w+) (\d+)-bit key · certificate sha256 (\S+) \(checked with (.+)\)",
     "Signatur: gültig · Verfahren $1 · $2-Schlüssel mit $3 Bit · Zertifikat-SHA-256 $4 (geprüft mit $5)"),
    (r"Signature: not valid \(checked with (.+)\)", "Signatur: ungültig (geprüft mit $1)"),
    (rf"{N} of ([\d,]+) methods \(([\d.]+%)\) could not be decompiled and were not checked, in {N} class(?:es)?: (.+)\.",
     "$1 von $2 Methoden ($3) konnten nicht dekompiliert werden und wurden nicht geprüft, in $4 Klasse(n): $5."),
    (r"Reverse-engineered with the fast engine \(jadx\) instead of the deep engine \((.+)\)\. Results are complete, but line numbers differ from deep-engine scans of the same app\.",
     "Mit der schnellen Engine (jadx) statt der gründlichen Engine zurückentwickelt ($1). Die Ergebnisse sind vollständig, aber die Zeilennummern weichen von gründlichen Scans derselben App ab."),
    # ---- plans and checkout
    (r"Fix it for (\$[\d.,]+)", "Für $1 beheben"),
    (r"Improve it for (\$[\d.,]+)", "Für $1 verbessern"),
    (r"Unlock for (\$[\d.,]+)", "Für $1 freischalten"),
    (r"(.+) is coming soon\.", "$1 kommt bald."),
    (rf"{N} critical · {N} warnings · {N} smells", "$1 kritisch · $2 Warnungen · $3 Smells"),
    (r"Pay (\$[\d.,]+) \(demo\)", "$1 bezahlen (Demo)"),
    # ---- source preview and fixing
    (rf"Secure & Auto-Fix would work on {N} issues? \({N} places?\) and keep only fixes a re-scan proves\.",
     "Secure & Auto-Fix würde $1 Problem(e) an $2 Stelle(n) angehen und nur Korrekturen behalten, die ein erneuter Scan beweist."),
    (r"1 leaked key must be revoked by you; we explain how\.", "1 geleakter Schlüssel muss von dir gesperrt werden; wir erklären, wie."),
    (rf"{N} leaked keys must be revoked by you; we explain how\.", "$1 geleakte Schlüssel müssen von dir gesperrt werden; wir erklären, wie."),
    (rf"For your safety we did not keep {N} secret files? from the zip \(signing keys, local settings\): (.+)",
     "Zu deiner Sicherheit haben wir $1 geheime Datei(en) aus der ZIP-Datei nicht übernommen (Signaturschlüssel, lokale Einstellungen): $2"),
    (rf"fixes the {N} critical issues? and warnings? above\.", "behebt die $1 kritischen Probleme und Warnungen oben."),
    (rf"also fixes {N} smells?, reviews {N} structure problems? with a refactoring plan for each, and gives you a ready-to-open pull request\.",
     "behebt zusätzlich $1 Smell(s), prüft $2 Strukturproblem(e) mit je einem Refactoring-Plan und liefert dir einen fertigen Pull Request."),
    (rf"(\w+)\(\) in (\S+) · {N} lines, {N} parameters · SonarSource (java:S\d+)", "$1() in $2 · $3 Zeilen, $4 Parameter · SonarSource $5"),
    (rf"{N} of {N} issues done", "$1 von $2 Problemen erledigt"),
    (r"✓ Paid · (.+)", "✓ Bezahlt · $1"),
    (rf"{N} of {N} issues fixed and proven by a re-scan", "$1 von $2 Problemen behoben und durch erneuten Scan bewiesen"),
    (r"New problems: (.+)", "Neue Probleme: $1"),
    (r"Apply with: git apply fixes\.patch · patch sha256 (\S+) · before (\w+) → after (\w+)",
     "Anwenden mit: git apply fixes.patch · Patch-SHA-256 $1 · vorher $2 → nachher $3"),
    (rf"{N} issues? · review every change", "$1 Problem(e) · prüfe jede Änderung"),
    (r"Why not: (.+)", "Warum nicht: $1"),
    (r"How to fix it yourself: (.+)", "So behebst du es selbst: $1"),
    (rf"{N} · suggestions, not applied", "$1 · Vorschläge, nicht angewendet"),
    (rf"No method is over {N} lines or {N} parameters\.", "Keine Methode hat mehr als $1 Zeilen oder $2 Parameter."),
    (r"Test this: (.+)", "Teste das: $1"),
    (rf"{N} smells? left as they were:", "$1 Smell(s) unverändert gelassen:"),
    (r"Checked (.+)\. Fixes written by (.+) · severity policy ([\d.]+) · took (\d+)s",
     "Geprüft: $1. Korrekturen geschrieben von $2 · Schweregrad-Richtlinie $3 · Dauer $4 s"),
    (rf"More than {N} issues; this one was not attempted\.", "Mehr als $1 Probleme; dieses wurde nicht versucht."),
    (r"The edit introduced a new problem the scanner flags: (.+)\.", "Die Änderung hat ein neues Problem eingeführt, das der Scanner meldet: $1."),
    (r"The AI service failed: (.+)", "Der KI-Dienst ist ausgefallen: $1"),
    (rf"The zip is larger than {N} MB\.", "Die ZIP-Datei ist größer als $1 MB."),
    (rf"The zip has more than {N} files\. Leave out build folders and try again\.", "Die ZIP-Datei hat mehr als $1 Dateien. Lass Build-Ordner weg und versuch es erneut."),
    (r"The zip contains an unsafe path: (.+)", "Die ZIP-Datei enthält einen unsicheren Pfad: $1"),
]


def exact() -> dict[str, str]:
    """Every English sentence the pages can show, with its German text."""
    from scanner.policy import RULES as POLICY

    out = {**PAGES, **LANDING, **LANDING_FRIENDLY, **LANDING_WAITLIST, **REPORT_DOWNLOAD, **EXPLORER, **SERVER, **STRUCTURE, **WORDS}
    for rule_id, (title, risk, fix) in RULES.items():
        if rule_id in POLICY:
            p = POLICY[rule_id]
            out[p.title], out[p.risk], out[p.fix] = title, risk, fix
    return {" ".join(k.split()): v for k, v in out.items()}


def write_js(path: Path = Path(__file__).resolve().parent.parent / "static" / "i18n-de.js") -> Path:
    data = {"exact": exact(), "patterns": [[p, r] for p, r in PATTERNS], "terms": [[a, b] for a, b in TERMS]}
    path.write_text("/* Generated by `python -m scanner.i18n_de` from scanner/i18n_de.py - edit that file, not this one. */\n"
                    f"window.VG_DE = {json.dumps(data, ensure_ascii=False, indent=0)};\n", encoding="utf-8",
                    newline="\n")
    return path


# The landing page for people who build with AI (plain words, no jargon).
LANDING_FRIENDLY = {
    "Check my app free": "Meine App kostenlos prüfen",
    "Check my app free →": "Meine App kostenlos prüfen →",
    "✨ Made for people who build with AI": "✨ Für alle, die mit KI bauen",
    "You built it with AI.": "Du hast es mit KI gebaut.",
    "Now make sure it's safe.": "Jetzt sorg dafür, dass es sicher ist.",
    "Drop in your app or paste your website link. VibeGuard checks it for leaked keys, open data and hidden bugs, "
    "and tells you in plain words what to fix. No coding knowledge needed.":
        "Lade deine App hoch oder füge den Link zu deiner Website ein. VibeGuard prüft sie auf geleakte Schlüssel, "
        "offene Daten und versteckte Fehler und sagt dir in einfachen Worten, was zu tun ist. Ganz ohne "
        "Programmierkenntnisse.",
    "See an example": "Ein Beispiel ansehen",
    "Free · about a minute · no card needed": "Kostenlos · etwa eine Minute · keine Karte nötig",
    "An example check-up": "Ein Beispiel-Check",
    "Your check-up": "Dein Check",
    "example": "Beispiel",
    "Fix right away": "Sofort beheben",
    "Tidy up later": "Später aufräumen",
    "What this means": "Was das bedeutet",
    "📋 Copy the fix for my AI tool": "📋 Korrektur für mein KI-Tool kopieren",
    "A real check of our demo website, which has problems planted on purpose.":
        "Ein echter Check unserer Demo-Website, in die absichtlich Probleme eingebaut sind.",
    "Built it with any of these? VibeGuard checks what they made.":
        "Mit einem dieser Tools gebaut? VibeGuard prüft, was sie erstellt haben.",
    "What can go wrong (and nobody tells you)": "Was schiefgehen kann (und dir keiner sagt)",
    "AI tools build fast, but they don't warn you about these. VibeGuard does.":
        "KI-Tools bauen schnell, aber sie warnen dich nicht davor. VibeGuard schon.",
    "Your secret keys are public": "Deine geheimen Schlüssel sind öffentlich",
    "AI often puts API keys straight into your app. Anyone can copy them and run up your bill.":
        "KI schreibt API-Schlüssel oft direkt in deine App. Jeder kann sie kopieren und dir hohe Rechnungen bescheren.",
    "Strangers can see your data": "Fremde können deine Daten sehen",
    "A leaked admin key or settings file can let anyone read, change or delete your users' data.":
        "Ein geleakter Admin-Schlüssel oder eine Einstellungsdatei kann jedem erlauben, die Daten deiner Nutzer zu "
        "lesen, zu ändern oder zu löschen.",
    "Logins that can be stolen": "Anmeldungen, die gestohlen werden können",
    "Login details kept in the wrong place can be grabbed by a single bad script.":
        "Anmeldedaten am falschen Ort kann ein einziges bösartiges Skript abgreifen.",
    "Bugs that crash or leak": "Fehler, die abstürzen oder Daten verlieren",
    "Small mistakes that make your app crash, freeze, or quietly lose data.":
        "Kleine Fehler, durch die deine App abstürzt, hängt oder still und leise Daten verliert.",
    "Three steps. About a minute.": "Drei Schritte. Etwa eine Minute.",
    "No setup, nothing to install, no technical words.": "Keine Einrichtung, nichts zu installieren, keine Fachbegriffe.",
    "Drop it in": "Hochladen",
    "Your Android app file, your website's address, or a zip of your project.":
        "Deine Android-App-Datei, die Adresse deiner Website oder eine ZIP-Datei deines Projekts.",
    "We check it": "Wir prüfen es",
    "Security checks a professional would run: leaked keys, unsafe settings, open data and common bugs.":
        "Sicherheitsprüfungen wie von einem Profi: geleakte Schlüssel, unsichere Einstellungen, offene Daten und "
        "typische Fehler.",
    "Get a simple to-do list": "Eine einfache To-do-Liste bekommen",
    "Free: see what's wrong. For $9, every problem in plain words with a fix you can paste into your AI tool. Or we fix it for you.":
        "Kostenlos: sieh, was nicht stimmt. Für 9 $ jedes Problem in einfachen Worten, mit einer Korrektur, die du in "
        "dein KI-Tool einfügen kannst. Oder wir beheben es für dich.",
    "A to-do list you'll actually understand": "Eine To-do-Liste, die du wirklich verstehst",
    "Every problem says what it is, why it matters and exactly what to do. Not sure how? Copy the ready-made "
    "instructions and paste them into the AI tool you built with.":
        "Bei jedem Problem steht, was es ist, warum es wichtig ist und was genau zu tun ist. Nicht sicher, wie? "
        "Kopiere die fertige Anleitung und füge sie in das KI-Tool ein, mit dem du gebaut hast.",
    "Sorted by what to fix first": "Sortiert danach, was zuerst behoben werden sollte",
    "Explained in everyday words": "Erklärt in Alltagssprache",
    "One click to copy the fix for your AI tool": "Ein Klick, um die Korrektur für dein KI-Tool zu kopieren",
    "Why it matters": "Warum es wichtig ist",
    "What to do": "Was zu tun ist",
    "Why you can trust the results": "Warum du den Ergebnissen trauen kannst",
    "No guessing": "Kein Raten",
    "Problems are found by proven security checks, not by an AI's opinion. The AI only explains them.":
        "Probleme werden von bewährten Sicherheitsprüfungen gefunden, nicht von der Meinung einer KI. Die KI erklärt "
        "sie nur.",
    "Same app, same answer": "Gleiche App, gleiche Antwort",
    "Check the same app again and you get exactly the same result, every time.":
        "Prüfe dieselbe App noch einmal, und du bekommst genau dasselbe Ergebnis – jedes Mal.",
    "Your code stays yours": "Dein Code bleibt deiner",
    "Uploads are deleted after 24 hours, and secret files are never kept. You can only check what you own.":
        "Uploads werden nach 24 Stunden gelöscht, und geheime Dateien werden nie gespeichert. Du kannst nur prüfen, "
        "was dir gehört.",
    "Start free. Pay only if you need more.": "Starte kostenlos. Zahl nur, wenn du mehr brauchst.",
    "No subscription. Every check is free to try.": "Kein Abo. Jeder Check ist kostenlos zum Ausprobieren.",
    "Free check": "Kostenloser Check",
    "See what's wrong": "Sieh, was nicht stimmt",
    "How many problems, and what they are": "Wie viele Probleme es gibt und welche",
    "free checks a day": "kostenlose Checks pro Tag",
    "Checking the same app again is free": "Dieselbe App erneut zu prüfen ist kostenlos",
    "Know exactly what to fix": "Wisse genau, was zu beheben ist",
    "once": "einmalig",
    "Where each problem is": "Wo jedes Problem steckt",
    "Why it matters, in plain words": "Warum es wichtig ist, in einfachen Worten",
    "A ready-made fix for your AI tool": "Eine fertige Korrektur für dein KI-Tool",
    "Check, then unlock": "Prüfen, dann freischalten",
    "Recommended": "Empfohlen",
    "We fix it for you": "Wir beheben es für dich",
    "The serious problems fixed in your code": "Die ernsten Probleme in deinem Code behoben",
    "Every fix double-checked": "Jede Korrektur doppelt geprüft",
    "Download your fixed project": "Lade dein korrigiertes Projekt herunter",
    "Fix my app": "Meine App beheben",
    "Fix it and tidy it up": "Beheben und aufräumen",
    "Everything in Bug fixing": "Alles aus der Fehlerbehebung",
    "Messy code cleaned up too": "Auch unordentlicher Code aufgeräumt",
    "A pull request ready to open": "Ein fertiger Pull Request",
    "Fix and tidy up": "Beheben und aufräumen",
    "I'm not a developer. Will I understand the results?": "Ich bin kein Entwickler. Verstehe ich die Ergebnisse?",
    "Yes. Every problem is explained in everyday words: what it is, what could happen, and what to do. You can "
    "also copy the fix and paste it straight into the AI tool you built with.":
        "Ja. Jedes Problem wird in Alltagssprache erklärt: was es ist, was passieren könnte und was zu tun ist. Du "
        "kannst die Korrektur auch kopieren und direkt in das KI-Tool einfügen, mit dem du gebaut hast.",
    "Does it work with Lovable, Bolt, Cursor or Replit?": "Funktioniert es mit Lovable, Bolt, Cursor oder Replit?",
    "Yes. VibeGuard checks what you ship: your Android app file, your live website, or your project's code. It "
    "doesn't matter which tool wrote it.":
        "Ja. VibeGuard prüft, was du veröffentlichst: deine Android-App-Datei, deine Live-Website oder den Code deines "
        "Projekts. Egal, welches Tool ihn geschrieben hat.",
    "No. The free check and the $9 report only need your app file or your website's address. You only upload your "
    "code if you want us to fix things for you.":
        "Nein. Der kostenlose Check und der Bericht für 9 $ brauchen nur deine App-Datei oder die Adresse deiner "
        "Website. Deinen Code lädst du nur hoch, wenn wir etwas für dich beheben sollen.",
    "Is it safe to upload my app or code?": "Ist es sicher, meine App oder meinen Code hochzuladen?",
    "Uploads are deleted after 24 hours, and secret files such as signing keys and .env files are never kept. You "
    "can only check apps and websites you own or have permission to test.":
        "Uploads werden nach 24 Stunden gelöscht, und geheime Dateien wie Signaturschlüssel und .env-Dateien werden "
        "nie gespeichert. Du kannst nur Apps und Websites prüfen, die dir gehören oder die du testen darfst.",
    "What if it finds something serious?": "Was, wenn es etwas Ernstes findet?",
    "Start with the items marked \"Fix right away\". The report tells you exactly what to do, or choose Bug fixing "
    "and we fix it in your code for you. Every fix is checked again before you get it.":
        "Fang mit den Punkten an, die mit „Sofort beheben“ markiert sind. Der Bericht sagt dir genau, was zu tun ist, "
        "oder du wählst die Fehlerbehebung, und wir beheben es für dich in deinem Code. Jede Korrektur wird noch "
        "einmal geprüft, bevor du sie bekommst.",
    "Every fix is checked again before you get it, and fixes that could break other parts of your app are "
    "rejected. We can't run your app, so try it once before you publish; the report reminds you.":
        "Jede Korrektur wird noch einmal geprüft, bevor du sie bekommst, und Korrekturen, die andere Teile deiner App "
        "kaputt machen könnten, werden verworfen. Wir können deine App nicht starten, probier sie also einmal aus, "
        "bevor du veröffentlichst; der Bericht erinnert dich daran.",
    "Check your app before your users find the problems.": "Prüfe deine App, bevor deine Nutzer die Probleme finden.",
    "Free, about a minute, no card needed.": "Kostenlos, etwa eine Minute, keine Karte nötig.",
    "© VibeGuard · Only check apps and websites you own or may test.":
        "© VibeGuard · Prüfe nur Apps und Websites, die dir gehören oder die du testen darfst.",
    "For the technical folks: findings follow OWASP MASVS / ASVS and CWE; built on jadx, Semgrep, Gitleaks and apksig plus VibeGuard's own deep engine.":
        "Für Technikinteressierte: Die Befunde folgen OWASP MASVS / ASVS und CWE; basiert auf jadx, Semgrep, Gitleaks und apksig sowie der eigenen gründlichen Engine von VibeGuard.",
    "The website's .env file can be downloaded": "Die .env-Datei der Website kann heruntergeladen werden",
}


# Melina's landing page (static/landing.html): waitlist, the three packages, what we check, FAQ.
LANDING_WAITLIST = {
    "Quick-Scan & Report": "Quick-Scan & Report",
    "Secure & Auto-Fix": "Secure & Auto-Fix",
    "Deep Architecture Audit": "Deep Architecture Audit",
    "VibeGuard — Knowing it's safe to ship is the hard part": "VibeGuard — Zu wissen, dass man sicher veröffentlichen kann, ist der schwierige Teil",
    "Skip to content": "Zum Inhalt springen",
    "Apply for waitlist": "Auf die Warteliste",
    "Try it free": "Kostenlos testen",
    "Building with AI is easy.": "Mit KI zu bauen ist einfach.",
    "Knowing it's safe to ship is the hard part.": "Zu wissen, dass man sicher veröffentlichen kann, ist der schwierige Teil.",
    "VibeGuard checks the website or Android app you already shipped. Get a report, have us fix it, or get an audit you can show someone else.": "VibeGuard prüft die Website oder Android-App, die du schon veröffentlicht hast. Hol dir einen Bericht, lass sie von uns reparieren oder bekomme ein Audit, das du anderen zeigen kannst.",
    "Free scan · about a minute · no card needed ·": "Kostenloser Scan · etwa eine Minute · keine Karte nötig ·",
    "see an example report": "Beispielbericht ansehen",
    "Three different jobs.": "Drei verschiedene Aufgaben.",
    "A report, the fixes, or a full audit. One app. No subscription.": "Ein Bericht, die Korrekturen oder ein komplettes Audit. Eine App. Kein Abo.",
    "See it clearly": "Klar sehen",
    "We fix it": "Wir reparieren es",
    "Proof you can hand over": "Ein Nachweis zum Weitergeben",
    "A short report on the app you already shipped.": "Ein kurzer Bericht über die App, die du schon veröffentlicht hast.",
    "What's risky, and what's already fine": "Was riskant ist und was schon passt",
    "What to do first, in plain language": "Was du zuerst tun solltest, in einfachen Worten",
    "The report, then the safe fixes done for you.": "Der Bericht, dann die sicheren Korrekturen für dich.",
    "Security holes in your code fixed, and leaked keys explained step by step": "Sicherheitslücken in deinem Code behoben und geleakte Schlüssel Schritt für Schritt erklärt",
    "A second check, so you can see what changed": "Eine zweite Prüfung, damit du siehst, was sich geändert hat",
    "A deeper look at how the app is actually built.": "Ein genauerer Blick darauf, wie die App wirklich gebaut ist.",
    "Evidence next to every finding": "Belege neben jedem Befund",
    "A \"What we checked\" certificate you can show a client, a customer or an investor": "Ein Zertifikat „Was wir geprüft haben“, das du einem Auftraggeber, Kunden oder Investor zeigen kannst",
    "$199 website · $249 Android or both": "199 $ Website · 249 $ Android oder beides",
    "Apply for waitlist.": "Auf die Warteliste.",
    "Leave your name. We'll write back.": "Hinterlasse deinen Namen. Wir melden uns.",
    "Name": "Name",
    "Package": "Paket",
    "Choose a package": "Paket wählen",
    "Link or app name": "Link oder App-Name",
    "Optional": "Optional",
    "https:// or the name of the app": "https:// oder der Name der App",
    "VibeGuard · Team 4": "VibeGuard · Team 4",
    "Thanks! We'll write back soon.": "Danke! Wir melden uns bald.",
    "Get early access": "Früher Zugang",
    "Get early access →": "Früher Zugang →",
    "The free scan opens soon. Join the waitlist to be the first to try it.": "Der kostenlose Scan startet bald. Trag dich in die Warteliste ein, um ihn als Erste:r zu testen.",
    "We only use your details to write back about VibeGuard. Ask us any time and we'll delete them.": "Wir nutzen deine Angaben nur, um dir zu VibeGuard zu antworten. Sag uns jederzeit Bescheid, dann löschen wir sie.",
    "We couldn't save that. Please check your email address and try again.": "Das konnten wir nicht speichern. Bitte prüfe deine E-Mail-Adresse und versuch es erneut.",
    "We couldn't save that. Please try again.": "Das konnten wir nicht speichern. Bitte versuch es erneut.",
    "Please enter your name and email.": "Bitte gib deinen Namen und deine E-Mail-Adresse ein.",
    "👤 Logins and access": "👤 Logins und Zugriff",
    "What we check.": "Was wir prüfen.",
    "The mistakes AI coding tools make most often. Up to 70 checks, mapped to the OWASP Top 10.": "Die Fehler, die KI-Coding-Tools am häufigsten machen. Bis zu 70 Prüfungen, zugeordnet zu den OWASP Top 10.",
    "🔑 Leaked keys": "🔑 Geleakte Schlüssel",
    "API keys, tokens and passwords anyone can copy from your app or site.": "API-Schlüssel, Tokens und Passwörter, die jeder aus deiner App oder Website kopieren kann.",
    "🔒 Connections": "🔒 Verbindungen",
    "Data sent without HTTPS, fake certificates accepted, missing security headers.": "Daten ohne HTTPS, akzeptierte gefälschte Zertifikate, fehlende Sicherheits-Header.",
    "💉 Code that can be tricked": "💉 Code, der sich austricksen lässt",
    "SQL, HTML and commands built from what users type.": "SQL, HTML und Befehle, die aus Nutzereingaben gebaut werden.",
    "Weak login tokens, admin features unlocked in the browser, open CORS.": "Schwache Login-Tokens, im Browser freigeschaltete Admin-Funktionen, offenes CORS.",
    "📂 Exposed files": "📂 Offene Dateien",
    ".env files, backups, .git folders and source maps anyone can download.": ".env-Dateien, Backups, .git-Ordner und Source Maps, die jeder herunterladen kann.",
    "📦 Risky libraries": "📦 Riskante Bibliotheken",
    "Known security holes, and packages AI tools invented that attackers can register.": "Bekannte Sicherheitslücken und von KI-Tools erfundene Pakete, die Angreifer registrieren können.",
    "🕵️ Privacy": "🕵️ Datenschutz",
    "Trackers that start before consent, and the personal data your app can reach.": "Tracker, die vor der Einwilligung starten, und die persönlichen Daten, auf die deine App zugreifen kann.",
    "✍️ Settings": "✍️ Einstellungen",
    "Debug builds, unsafe app settings and how your Android or iPhone app is signed.": "Debug-Builds, unsichere App-Einstellungen und wie deine Android- oder iPhone-App signiert ist.",
    "Why you can trust it.": "Warum du dem vertrauen kannst.",
    "Rules find the problems. The AI explains them.": "Regeln finden die Probleme. Die KI erklärt sie.",
    "Same app, same result": "Gleiche App, gleiches Ergebnis",
    "Fixed security rules find and rate every problem, so checking again gives the same answer.": "Feste Sicherheitsregeln finden und bewerten jedes Problem, deshalb liefert eine erneute Prüfung dasselbe Ergebnis.",
    "Every fix proven": "Jede Korrektur bewiesen",
    "We keep a fix only when a second scan shows the problem is gone and nothing new broke.": "Wir behalten eine Korrektur nur, wenn ein zweiter Scan zeigt, dass das Problem weg ist und nichts Neues kaputtging.",
    "Uploads are deleted after 24 hours, secret files are never kept, and you can only check what you own.": "Uploads werden nach 24 Stunden gelöscht, geheime Dateien werden nie gespeichert, und du kannst nur prüfen, was dir gehört.",
    "Questions.": "Fragen.",
    "Do you keep my code?": "Speichert ihr meinen Code?",
    "No. Uploads and reports are deleted after 24 hours, and signing keys or .env files are never stored.": "Nein. Uploads und Berichte werden nach 24 Stunden gelöscht, und Signaturschlüssel oder .env-Dateien werden nie gespeichert.",
    "I don't have the source code. Can I still use it?": "Ich habe den Quellcode nicht. Kann ich es trotzdem nutzen?",
    "Yes. Send your Android app (.apk), your iPhone app (.ipa) or your website's address. Fixing needs the source code.": "Ja. Schick deine Android-App (.apk), deine iPhone-App (.ipa) oder die Adresse deiner Website. Für Korrekturen brauchen wir den Quellcode.",
    "Which apps work?": "Welche Apps funktionieren?",
    "Android and iPhone apps, websites, and projects in JavaScript, TypeScript, React, Next.js, Python, Kotlin or Java, including apps built with Lovable, Bolt, Cursor, Replit or v0.": "Android- und iPhone-Apps, Websites und Projekte in JavaScript, TypeScript, React, Next.js, Python, Kotlin oder Java, auch Apps, die mit Lovable, Bolt, Cursor, Replit oder v0 gebaut wurden.",
    "A real example.": "Ein echtes Beispiel.",
    "The \"What we checked\" certificate from a real scan of F-Droid, an open-source Android app store.": "Das Zertifikat „Was wir geprüft haben“ aus einem echten Scan von F-Droid, einem Open-Source-App-Store für Android.",
    "What we checked": "Was wir geprüft haben",
    "44 checks · OWASP Top 10:2025": "44 Prüfungen · OWASP Top 10:2025",
    "1 to fix right away": "1 sofort beheben",
    "4 warnings": "4 Warnungen",
    "9 to tidy up": "9 zum Aufräumen",
    "30 checks passed": "30 Prüfungen bestanden",
    "1 issue": "1 Problem",
    "2 issues": "2 Probleme",
    "3 issues": "3 Probleme",
    "4 issues": "4 Probleme",
    "Passed": "Bestanden",
    "Needs a person": "Braucht einen Menschen",
    "Partly checked": "Teilweise geprüft",
    "Every issue in the report comes with the file, the line and the evidence. Checking the same app again gives the same result.": "Zu jedem Problem im Bericht gibt es die Datei, die Zeile und den Beleg. Eine erneute Prüfung derselben App liefert dasselbe Ergebnis.",
    "Is an AI deciding what's wrong?": "Entscheidet eine KI, was falsch ist?",
    "No. Fixed security rules find and rate the problems; the AI explains them in plain words and writes fixes, which a second scan must prove.": "Nein. Feste Sicherheitsregeln finden und bewerten die Probleme; die KI erklärt sie in einfachen Worten und schreibt Korrekturen, die ein zweiter Scan bestätigen muss.",
    "A01 Broken Access Control": "A01 Fehlerhafte Zugriffskontrolle",
    "A02 Security Misconfiguration": "A02 Sicherheitsrelevante Fehlkonfiguration",
    "A03 Software Supply Chain Failures": "A03 Fehler in der Software-Lieferkette",
    "A04 Cryptographic Failures": "A04 Kryptografische Fehler",
    "A05 Injection": "A05 Injection",
    "A06 Insecure Design": "A06 Unsicheres Design",
    "A07 Authentication Failures": "A07 Fehler bei der Authentifizierung",
    "A08 Software or Data Integrity Failures": "A08 Fehler bei Software- oder Datenintegrität",
    "A09 Security Logging and Alerting Failures": "A09 Fehler bei Sicherheitsprotokollierung und Alarmierung",
    "A10 Mishandling of Exceptional Conditions": "A10 Fehlerhafte Behandlung von Ausnahmesituationen",
}


# The downloadable HTML report (scanner/report_html.py) and its button.
REPORT_DOWNLOAD = {
    "Download report (HTML)": "Bericht herunterladen (HTML)",
    "Security report": "Sicherheitsbericht",
    "Report downloaded from VibeGuard": "Bericht heruntergeladen von VibeGuard",
    "App scan": "App-Scan",
    "Website scan": "Website-Scan",
    "About this scan": "Über diesen Scan",
    "File": "Datei",
    "Website": "Website",
    "Scanned at": "Gescannt am",
    "Raw findings": "Rohbefunde",
    "Explained by": "Erklärt von",
    "Engine": "Engine",
    "severity policy": "Schweregrad-Richtlinie",
    "Tools": "Werkzeuge",
    "Signature": "Signatur",
    "valid": "gültig",
    "not valid": "ungültig",
    "Smell": "Smell",
    "Quick-Scan & Report": "Quick-Scan & Report",
    "Secret (shortened):": "Geheimnis (gekürzt):",
    "Note:": "Hinweis:",
    "Preparing your report. The first download in a new language takes about 30 seconds.":
        "Dein Bericht wird vorbereitet. Der erste Download in einer neuen Sprache dauert etwa 30 Sekunden.",
}


# The interactive issue explorer above a report (static/explorer.js).
EXPLORER = {
    "Issue explorer": "Problem-Explorer",
    "Analysing…": "Wird analysiert…",
    "Search issues, CWE, file…": "Probleme, CWE, Datei suchen…",
    "Search issues": "Probleme suchen",
    "Everything we found": "Alles, was wir gefunden haben",
    "Each tile is one place in your code: red is critical, amber a warning, blue a smell, grey a probable false alarm. Drag to spin it.":
        "Jede Kachel ist eine Stelle in deinem Code: Rot ist kritisch, Orange eine Warnung, Blau ein Smell, Grau ein "
        "wahrscheinlicher Fehlalarm. Zieh, um sie zu drehen.",
    "Every issue, tagged": "Jedes Problem, verschlagwortet",
    "Tap any tile to see its severity, its security standard and how many places it's in.":
        "Tippe auf eine Kachel, um Schweregrad, Sicherheitsstandard und die Zahl der Stellen zu sehen.",
    "Find anything": "Finde alles",
    "Search by name, CWE, OWASP control, kind or file name.":
        "Suche nach Name, CWE, OWASP-Kontrolle, Art oder Dateiname.",
    "Continue": "Weiter",
    "See all issues ↓": "Alle Probleme ansehen ↓",
    "Show in report": "Im Bericht zeigen",
    "Close": "Schließen",
    "Search for this": "Danach suchen",
    "No matches": "Keine Treffer",
    "1 match": "1 Treffer",
    "1 place": "1 Stelle",
    "Probably a false alarm": "Wahrscheinlich ein Fehlalarm",
}


if __name__ == "__main__":
    print(f"wrote {write_js()} ({len(exact())} sentences, {len(PATTERNS)} patterns)")
