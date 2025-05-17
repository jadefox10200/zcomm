Mission Statement
zcomm is a revolutionary communication platform designed to replace email with a secure, instant, and professional alternative for businesses, professionals, and client interactions. Powered by the zcomm Protocol (zCP) and zcomm Epistle Markup (zEM), zcomm delivers lightweight, encrypted dispatches presented as formal epistles—elegant, letter-like documents that combine the formality of traditional correspondence with modern cryptographic security and action-oriented functionality. Unlike email’s sloppiness, insecurity, and disorganization, zcomm offers end-to-end encryption, decentralized key management, no server storage, and structured conversation threading, ensuring privacy, authenticity, and efficiency. With features like via routing for approval workflows, conditional CC delivery, and QR code-based signature verification, zcomm empowers organizations to communicate with confidence, clarity, and professionalism, redefining digital correspondence for the 21st century.
Goals

Security and Privacy: Provide end-to-end encryption (AES-GCM, ECDH, Ed25519), minimal server metadata, and no long-term server storage, with decentralized key management to protect user data.
Professionalism: Deliver dispatches as formal epistles with rich formatting, letterhead logos, and embedded/appended attachments, rendered in a polished, printable GUI for business and client use.
Instant Delivery: Enable near-real-time dispatch delivery via push notifications and peer-to-peer (P2P) routing, eliminating email’s delays and zcomm’s current polling inefficiencies.
Action-Oriented Workflows: Support via routing for approval chains, conditional CC delivery, and threaded conversations to facilitate organized, actionable communication.
Authenticity: Embed QR codes in epistles for cryptographic signature verification, allowing any device to confirm dispatch authenticity, critical for legal and financial correspondence.
Scalability and Resilience: Scale to millions of users through a hybrid client-server and P2P architecture, with transient server queues and decentralized key directories for reliability.
Adoption: Overcome resistance to a new protocol by offering email interoperability (SMTP/IMAP bridges) and emphasizing zcomm’s security, privacy, and professional benefits.

Dispatch Flow
The dispatch flow in zcomm, powered by zCP, ensures secure, instant, and professional communication with support for via routing, conditional CC delivery, and authenticity verification. Here’s how it works:

Composition:

A sender (e.g., Alice) composes a dispatch in the zcomm GUI, specifying:
Recipient (to_zid, e.g., Bob).
Via intermediaries (via_zids, e.g., Jeff for approval).
CC recipients (cc_zids, e.g., team members).
Formal letter text, optional letterhead logo, and attachments (embedded or appended).
Conversation thread (conversation_id, seq_no).


The GUI formats the content in zEM, a text-based markup for epistles.


Encryption and Signing:

The client queries a decentralized key directory (FETCH_PUBLIC_KEYS) for recipients’ and intermediaries’ public keys (ECDHPub, EdPub).
The dispatch payload (zEM body, letterhead, attachments) is encrypted with AES-GCM using shared keys derived from ECDH (ephemeral keys for forward secrecy).
The dispatch is signed with the sender’s Ed25519 private key (EdPriv), producing a signature verifiable by all recipients.


Sending:

Client-Server: The client sends a SEND_DISPATCH message via zCP (TCP/TLS) to a relay server, targeting the first via_zids (Jeff) or to_zid (Bob) if no via. The server queues the dispatch transiently.
P2P: If recipients are online, the client delivers directly via zCP (UDP/DTLS) using decentralized discovery (e.g., Kademlia DHT).
Via Routing: For via dispatches, the server forwards to Jeff, who receives a NEW_DISPATCH notification and decrypts the dispatch.


Approval or Rejection (Via):

Jeff’s client displays the epistle with “Approve/Reject” options:
Approve: Jeff re-encrypts the dispatch for Bob and CC recipients, signs it with his EdPriv (forward_signature), and sends a new SEND_DISPATCH. The server forwards to Bob and sends CC copies only after approval.
Reject: Jeff sends a REJECT_DISPATCH to Alice, including a reason. The server discards the queue, ensuring no CC delivery.


Alice’s original signature is preserved, allowing Bob to verify authenticity.


Delivery and Verification:

Bob’s client receives a NEW_DISPATCH notification (via zCP push or mobile APNS/FCM), retrieves the dispatch, decrypts it, and verifies both Alice’s original signature and Jeff’s forward signature.
CC recipients receive and verify similarly, only after Jeff’s approval.
The epistle includes a QR code encoding dispatch_uuid, from_zid, and signature, scannable by any device to verify authenticity via a VERIFY_SIGNATURE message to a server or local client.


Storage and Threading:

The client stores the decrypted dispatch in SQLite, encrypted with a local key, linked to conversation_id and seq_no for threading.
The GUI organizes dispatches into threads, tracking actions (e.g., “awaiting response”) via the Baskets table.



Epistle Viewer
The zcomm epistle viewer is a native GUI component that renders dispatches as formal, printable letters, leveraging zEM for lightweight, secure formatting. Key features:

Presentation:
Formal Heading: Displays “From: Alice Smith”, “To: Bob Jones”, “CC: Team”, “Date: May 17, 2025”, “Subject: Contract Proposal” in a professional layout.
Letterhead: Shows the sender’s logo (e.g., Acme Corp) at the top, decrypted from zEM’s letterhead field, if provided.
Body: Renders zEM-formatted text (e.g., justified, Times New Roman) with lightweight markup (bold, italic, lists).
Attachments:
Embedded: Inline images or thumbnails (e.g., contract preview), decrypted on render.
Appended: Clickable links (e.g., “Download contract.pdf”), decrypted on access.


QR Code: Embedded image encoding dispatch_uuid, from_zid, and signature, scannable for verification.


Rendering: Native to the platform (e.g., SwiftUI for iOS, Qt for desktop, WebAssembly for web), ensuring security (no external viewers like PDF readers).
Printability: Optimized for standard paper sizes (A4, Letter), with consistent formatting across devices.
Interactivity: Supports actions (e.g., reply, forward, approve/reject for via dispatches), updating the Baskets table for workflow tracking.
Security: zEM’s text-based format contains no executable code, preventing injection attacks. Attachments are decrypted only when accessed, minimizing exposure.

### 📄 License

Zcomm is open-source under the [MIT License](LICENSE).
