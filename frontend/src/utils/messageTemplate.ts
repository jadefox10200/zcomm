import { Contact } from '../types';

/**
 * Parse closure and signature from combined string
 * @param closureStr - Combined closure and signature string
 * @returns Object with separate closure and signature
 */
export function parseClosureAndSignature(closureStr: string): { closure: string; signature: string } {
  if (!closureStr) {
    return { closure: '', signature: '' };
  }
  
  // Split by double newline to separate closure from signature
  const parts = closureStr.split('\n\n');
  if (parts.length >= 2) {
    return { closure: parts[0], signature: parts.slice(1).join('\n\n') };
  }
  
  // If no double newline, treat first line as closure, rest as signature
  const lines = closureStr.split('\n');
  if (lines.length >= 2) {
    return { closure: lines[0], signature: lines.slice(1).join('\n') };
  }
  
  return { closure: closureStr, signature: '' };
}

/**
 * Build a salutation string with the recipient's greeting name
 * @param salutationTemplate - Template string (e.g., "Dear [User],")
 * @param recipient - The contact or desk ID
 * @param contacts - List of contacts to search for greeting name
 * @returns Formatted salutation HTML
 */
export function buildSalutation(
  salutationTemplate: string,
  recipient: string,
  contacts: Contact[]
): string {
  if (!salutationTemplate) {
    return '';
  }

  // Find the contact by desk_id_ref
  const contact = contacts.find(c => c.desk_id_ref === recipient);
  
  // Use greeting_name if available, otherwise use first_name, otherwise use full name
  let recipientName = 'Sir/Madam';
  if (contact) {
    recipientName = contact.greeting_name || contact.first_name || contact.name;
  }

  // Replace [User] placeholder with the recipient's greeting name
  const salutation = salutationTemplate.replace(/\[User\]/gi, recipientName);
  
  // Return as HTML paragraph
  return `<p>${salutation}</p>`;
}

/**
 * Build a signature block with closure and signature
 * @param closureStr - Combined closure and signature string (separated by \n\n)
 * @returns Formatted signature HTML
 */
export function buildSignature(closureStr: string): string {
  if (!closureStr) {
    return '';
  }

  const { closure, signature } = parseClosureAndSignature(closureStr);
  
  if (signature) {
    // Convert newlines to <br> tags in signature
    const signatureHtml = signature.split('\n').map(line => line.trim()).filter(line => line).join('<br>');
    return `<p>${closure}</p><p>${signatureHtml}</p>`;
  }
  
  // Only closure, no signature
  return `<p>${closure}</p>`;
}

/**
 * Build complete message body with salutation, content, and signature
 * @param salutationTemplate - Salutation template
 * @param recipient - Recipient desk ID
 * @param contacts - List of contacts
 * @param closureStr - Combined closure and signature
 * @param bodyContent - The main message content (optional)
 * @returns Complete message HTML
 */
export function buildMessageWithTemplate(
  salutationTemplate: string,
  recipient: string,
  contacts: Contact[],
  closureStr: string,
  bodyContent: string = ''
): string {
  const salutation = buildSalutation(salutationTemplate, recipient, contacts);
  const signature = buildSignature(closureStr);
  
  // Combine parts with proper spacing
  const parts = [];
  if (salutation) parts.push(salutation);
  if (bodyContent) parts.push(bodyContent);
  if (signature) parts.push(signature);
  
  return parts.join('');
}
