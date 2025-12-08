import { buildSalutation, buildSignature, buildMessageWithTemplate, parseClosureAndSignature } from './messageTemplate';
import { Contact } from '../types';

describe('messageTemplate utilities', () => {
  const mockContacts: Contact[] = [
    {
      id: '1',
      desk_id: 'desk1',
      name: 'John Doe',
      first_name: 'John',
      last_name: 'Doe',
      greeting_name: 'Johnny',
      desk_id_ref: '5551234567',
      notes: '',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
    {
      id: '2',
      desk_id: 'desk2',
      name: 'Jane Smith',
      first_name: 'Jane',
      desk_id_ref: '5559876543',
      notes: '',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
  ];

  describe('parseClosureAndSignature', () => {
    it('should parse closure and signature with double newline separator', () => {
      const result = parseClosureAndSignature('Best Regards,\n\nJohn Doe\nCEO');
      expect(result.closure).toBe('Best Regards,');
      expect(result.signature).toBe('John Doe\nCEO');
    });

    it('should parse closure and signature with single newline separator', () => {
      const result = parseClosureAndSignature('Sincerely,\nJohn Doe');
      expect(result.closure).toBe('Sincerely,');
      expect(result.signature).toBe('John Doe');
    });

    it('should handle single line (no signature)', () => {
      const result = parseClosureAndSignature('Best Regards,');
      expect(result.closure).toBe('Best Regards,');
      expect(result.signature).toBe('');
    });

    it('should handle empty string', () => {
      const result = parseClosureAndSignature('');
      expect(result.closure).toBe('');
      expect(result.signature).toBe('');
    });
  });

  describe('buildSalutation', () => {
    it('should replace [User] with greeting_name when available', () => {
      const result = buildSalutation('Dear [User],', '5551234567', mockContacts);
      expect(result).toBe('<p>Dear Johnny,</p>');
    });

    it('should replace [User] with first_name when greeting_name is not available', () => {
      const result = buildSalutation('Dear [User],', '5559876543', mockContacts);
      expect(result).toBe('<p>Dear Jane,</p>');
    });

    it('should use default when contact is not found', () => {
      const result = buildSalutation('Dear [User],', '5550000000', mockContacts);
      expect(result).toBe('<p>Dear Sir/Madam,</p>');
    });

    it('should handle empty salutation template', () => {
      const result = buildSalutation('', '5551234567', mockContacts);
      expect(result).toBe('');
    });

    it('should be case insensitive for [User] placeholder', () => {
      const result = buildSalutation('Dear [user],', '5551234567', mockContacts);
      expect(result).toBe('<p>Dear Johnny,</p>');
    });
  });

  describe('buildSignature', () => {
    it('should split closure and signature with double newline', () => {
      const result = buildSignature('Best Regards,\n\nJohn Doe\nCEO\nCompany Inc.');
      expect(result).toBe('<p>Best Regards,</p><p>John Doe<br>CEO<br>Company Inc.</p>');
    });

    it('should split closure and signature with single newline', () => {
      const result = buildSignature('Sincerely,\nJohn Doe\nCEO');
      expect(result).toBe('<p>Sincerely,</p><p>John Doe<br>CEO</p>');
    });

    it('should handle single line closure', () => {
      const result = buildSignature('Best Regards,');
      expect(result).toBe('<p>Best Regards,</p>');
    });

    it('should handle empty closure', () => {
      const result = buildSignature('');
      expect(result).toBe('');
    });
  });

  describe('buildMessageWithTemplate', () => {
    it('should build complete message with all parts', () => {
      const result = buildMessageWithTemplate(
        'Dear [User],',
        '5551234567',
        mockContacts,
        'Best Regards,\n\nJohn Doe',
        '<p>This is my message.</p>'
      );
      expect(result).toContain('<p>Dear Johnny,</p>');
      expect(result).toContain('<p>This is my message.</p>');
      expect(result).toContain('<p>Best Regards,</p>');
      expect(result).toContain('<p>John Doe</p>');
    });

    it('should handle empty body content', () => {
      const result = buildMessageWithTemplate(
        'Dear [User],',
        '5551234567',
        mockContacts,
        'Best Regards,'
      );
      expect(result).toContain('<p>Dear Johnny,</p>');
      expect(result).toContain('<p>Best Regards,</p>');
    });
  });
});
