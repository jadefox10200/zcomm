zcomm Epistle Markup (zEM) Syntax Specification
Overview
zcomm Epistle Markup (zEM) is a lightweight, text-based markup language for formatting dispatches as formal epistles in the zcomm platform. Epistles are rendered client-side in the React Native GUI as professional, printable letters, combining traditional correspondence aesthetics with modern cryptographic security. zEM is embedded in the body field of zCP’s SendDispatch message, encrypted with AES-GCM, and supports secure, structured rendering without executable code.
This specification defines zEM for Phase 1 of zcomm’s implementation, focusing on minimal features for the epistle viewer: formal headings, basic body text with lightweight formatting, QR codes for signature verification, and text-based user signatures. Future phases will extend zEM for letterheads, embedded/appended attachments, and image-based signatures.
Syntax Rules
zEM uses a Markdown-like syntax with tags and key-value pairs, designed for easy parsing in JavaScript (React Native). The following rules apply:

Tags: Sections are denoted by square brackets (e.g., [epistle], [body]), starting on a new line.
Metadata: The [epistle] tag contains key-value pairs (e.g., from: value), one per line, using : as the separator.
Body: The [body] tag is followed by text, supporting lightweight markup (**bold**, *italic*).
QR Code: The [qrcode] tag contains key-value pairs for verification data.
Signature: The [signature] tag contains a user-defined text closure, automatically inserted or replaced via a placeholder.
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
May include a [signature] placeholder, replaced by the client with the stored closure.
Example:[body]
Dear Bob,

Welcome to our **new** platform. Please review the *proposal* below.

[signature]




[signature]:

Contains a user-defined text closure (e.g., “Sincerely, Alice Smith”).
Inserted automatically by the client during dispatch composition or replaces a [signature] placeholder in [body].
Stored client-side in SQLite, encrypted with a local key, set via the client’s settings.
Multi-line text is supported, with newlines preserved.
Example:[signature]
Sincerely,
Alice Smith




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

Supported Features: Headings (from, to, date, subject), body text with bold/italic, QR code, text-based signatures.
Excluded Features: Letterheads, embedded/appended attachments, image-based signatures, lists, tables, justified text (deferred to Phase 2).
Parsing: Clients must validate zEM input, rejecting malformed tags or unauthorized fields to ensure security.
Signature Storage: Text closures are stored in a Signatures table in SQLite, encrypted, with a single default closure per user.

Parsing Guidelines
For React Native implementation:

Split Tags: Use newlines to separate tags (e.g., split on \n and check for [tag]).
Parse Metadata: Extract [epistle] and [qrcode] fields with regex (e.g., (\w+): (.+)).
Render Body: Use a Markdown library (e.g., react-native-markdown-display) or replace **text**/*text* with <Text> styles.
Handle Signatures: Replace [signature] in [body] with the stored closure from SQLite, or append [signature] if not present.
Generate QR Code: Pass [qrcode] fields to react-native-qrcode-svg for rendering.
Sanitization: Strip any HTML-like tags (e.g., <script>) to prevent injection.

Signature Storage and Usage

Storage: Store the default text closure in a SQLite Signatures table:
Schema: Signatures (user_zid TEXT PRIMARY KEY, closure TEXT).
Encrypt closure with a local key (e.g., AES derived from user credentials).


Settings: Provide a React Native settings screen to input/edit the closure (e.g., a text input field).
Composition: During dispatch composition, the client:
Appends [signature] with the stored closure to [body] if no placeholder is used.
Replaces [signature] in [body] with the stored closure if present.


Security: Ensure closures are sanitized (e.g., no <script>) and encrypted in SQLite.

Example Epistle
Below is a complete zEM example for testing the Phase 1 epistle viewer, including a signature:
[epistle]
from: Alice Smith <z756724442>
to: Bob Jones <z123456789>
date: 2025-05-17T12:08:00-07:00
subject: Contract Proposal
[body]
Dear Bob,

Welcome to our **new** platform. Please review the *proposal* below.

[signature]
Sincerely,
Alice Smith
[qrcode]
uuid: 550e8400-e29b-41d4-a716-446655440000
from_zid: z756724442
signature: MC4CAQAwBQYDK2VwBCIEIL3bK5...

Future Extensions
In Phase 2, zEM will support:

[letterhead] id: <image_id> for logos.
[attachment:embedded] id: <id>, type: <mime> for inline images (e.g., signature PNGs).
[attachment:appended] id: <id>, type: <mime>, name: <filename> for downloadable files.
Advanced markup: Lists (- item), tables, justified text.
Image-based signatures stored client-side and embedded via [attachment:embedded].

This specification provides a foundation for Phase 1, with extensibility for future features.
