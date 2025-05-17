zcomm Epistle Markup (zEM) Syntax Specification
Overview
zcomm Epistle Markup (zEM) is a lightweight, text-based markup language for formatting dispatches as formal epistles in the zcomm platform. Epistles are rendered client-side in the React Native GUI as professional, printable letters, combining traditional correspondence aesthetics with modern cryptographic security. zEM is embedded in the body field of zCP’s SendDispatch message, encrypted with AES-GCM, and supports secure, structured rendering without executable code.
This specification defines zEM for Phase 1 of zcomm’s implementation, focusing on minimal features for the epistle viewer: formal headings, basic body text with lightweight formatting, and QR codes for signature verification. Future phases will extend zEM for letterheads, embedded/appended attachments, and advanced formatting.
Syntax Rules
zEM uses a Markdown-like syntax with tags and key-value pairs, designed for easy parsing in JavaScript (React Native). The following rules apply:

Tags: Sections are denoted by square brackets (e.g., [epistle], [body]), starting on a new line.
Metadata: The [epistle] tag contains key-value pairs (e.g., from: value), one per line, using : as the separator.
Body: The [body] tag is followed by text, supporting lightweight markup (**bold**, *italic*).
QR Code: The [qrcode] tag contains key-value pairs for verification data.
Delimiters: Tags and fields are separated by newlines (\n). No nested tags are allowed.
Security: No executable code, scripts, or external references (e.g., URLs) are permitted.
Encoding: UTF-8, with fields sanitized to prevent injection (e.g., no <script>).

Tags and Fields

[epistle]:

Defines metadata for the epistle’s heading.
Fields (one per line, key: value):
from: Sender’s name and zID (e.g., Alice Smith <z756724442>).
to: Recipient’s name and zID (e.g., Bob Jones <z123456789>).
date: ISO 8601 timestamp (e.g., 2025-05-17T12:08:00-07:00).
subject: Epistle subject (e.g., Contract Proposal).


Optional fields (Phase 2): cc, letterhead.
Example:[epistle]
from: Alice Smith <z756724442>
to: Bob Jones <z123456789>
date: 2025-05-17T12:08:00-07:00
subject: Contract Proposal




[body]:

Contains the epistle’s main text, starting on the line after [body].
Supports Markdown-like markup:
**text**: Bold text (e.g., **Welcome** renders as Welcome).
*text*: Italic text (e.g., *proposal* renders as proposal).


Plain text is rendered as-is, with newlines preserved as paragraphs.
Example:[body]
Dear Bob,

Welcome to our **new** platform. Please review the *proposal* below.

Sincerely,
Alice




[qrcode]:

Defines data for a QR code used in signature verification.
Fields (one per line, key: value):
uuid: Dispatch UUID (e.g., 550e8400-e29b-41d4-a716-446655440000).
from_zid: Sender’s zID (e.g., z756724442).
signature: Base64-encoded Ed25519 signature.


The client renders these as a QR code (e.g., using react-native-qrcode-svg).
Example:[qrcode]
uuid: 550e8400-e29b-41d4-a716-446655440000
from_zid: z756724442
signature: MC4CAQAwBQYDK2VwBCIEIL3bK5...





Phase 1 Limitations

Supported Features: Headings (from, to, date, subject), body text with bold/italic, QR code.
Excluded Features: Letterheads, embedded/appended attachments, lists, tables, justified text (deferred to Phase 2).
Parsing: Clients must validate zEM input, rejecting malformed tags or unauthorized fields to ensure security.

Parsing Guidelines
For React Native implementation:

Split Tags: Use newlines to separate tags (e.g., split on \n and check for [tag]).
Parse Metadata: Extract [epistle] fields with regex (e.g., (\w+): (.+)).
Render Body: Use a Markdown library (e.g., react-native-markdown-display) or replace **text**/*text* with <Text> styles.
Generate QR Code: Pass [qrcode] fields to react-native-qrcode-svg for rendering.
Sanitization: Strip any HTML-like tags (e.g., <script>) to prevent injection.

Example Epistle
Below is a complete zEM example for testing the Phase 1 epistle viewer:
[epistle]
from: Alice Smith <z756724442>
to: Bob Jones <z123456789>
date: 2025-05-17T12:08:00-07:00
subject: Contract Proposal
[body]
Dear Bob,

Welcome to our **new** platform. Please review the *proposal* below.

Sincerely,
Alice
[qrcode]
uuid: 550e8400-e29b-41d4-a716-446655440000
from_zid: z756724442
signature: MC4CAQAwBQYDK2VwBCIEIL3bK5...

Future Extensions
In Phase 2, zEM will support:

[letterhead] id: <image_id> for logos.
[attachment:embedded] id: <id>, type: <mime> for inline images.
[attachment:appended] id: <id>, type: <mime>, name: <filename> for downloadable files.
Advanced markup: Lists (- item), tables, justified text.

This specification provides a foundation for Phase 1, with extensibility for future features.
