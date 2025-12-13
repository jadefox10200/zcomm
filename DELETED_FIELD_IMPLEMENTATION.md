# Deleted Field Implementation

## Overview

Implemented a `deleted` flag on the `conversation_mivs` table to simplify basket filtering logic and provide a clean way to hide ACK conversations without losing data.

## Architecture Goals

- **Simple SQL Queries**: Each basket can be queried with straightforward WHERE clauses
- **Database-level Filtering**: No complex filtering logic in frontend or storage layer
- **Data Preservation**: Deleted conversations are hidden but not removed from database
- **Performance**: Compound index on (arrow_to, state, deleted) for fast basket queries

## Database Changes

### Schema Updates

1. **Added `deleted` column** to `conversation_mivs` table:

   ```sql
   ALTER TABLE conversation_mivs ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT 0;
   ```

2. **Created performance index**:

   ```sql
   CREATE INDEX idx_conversation_mivs_arrow_to_state
   ON conversation_mivs(arrow_to, state, deleted);
   ```

3. **Updated schema.sql** (line 62) for future database initialization

### Query Pattern

All basket queries now use:

```sql
SELECT * FROM conversation_mivs
WHERE arrow_to = ?
  AND state = ?
  AND deleted = 0
```

## Backend Changes

### Models (backend/internal/models/conversation.go)

- Added `Deleted bool` field to `ConversationMiv` struct
- Field serializes as `"deleted"` in JSON responses

### Storage Layer (backend/internal/storage/sqlite.go)

Updated all query functions to filter by `deleted = 0`:

1. **CreateConversationMiv**: Includes deleted field in INSERT
2. **GetConversationMiv**: Filters by `deleted = 0`
3. **GetConversationMivs**: Filters by `deleted = 0`
4. **MarkConversationMivAsRead**: Filters by `deleted = 0` in all queries
5. **MarkConversationMivsAsRead**: Filters by `deleted = 0`
6. **DeleteConversationMivs** (NEW): Sets `deleted = 1` for all mivs in a conversation

### API Layer (backend/internal/api/)

#### server.go

- Added `DeleteConversationMivs` method to `StorageBackend` interface
- Added route: `DELETE /api/conversations/:id` → `deleteConversation` handler

#### handlers.go

- **deleteConversation** (NEW): Handler to mark conversation mivs as deleted
  - Requires `desk_id` query parameter
  - Verifies conversation ownership
  - Sets `deleted = 1` for all mivs in conversation

## Frontend Changes

### Types (frontend/src/types/index.ts)

- Added `deleted: boolean` field to `ConversationMiv` interface

### API Client (frontend/src/api/client.ts)

- **deleteConversation** (NEW): Calls `DELETE /api/conversations/:id?desk_id=`

### Components

- **MivDetailWithContext.tsx**: Added `deleted: false` to optimistic updates

## Basket Query Logic

### Before (Complex)

- Backend filters by state and is_archived
- Frontend filters out archived conversations for non-archived baskets
- ACK deletion logic unclear

### After (Simple)

Each basket uses pure SQL:

- **Inbox**: `WHERE arrow_to=? AND state='IN' AND deleted=0`
- **Pending**: `WHERE arrow_to=? AND state='PENDING' AND deleted=0`
- **Sent**: `WHERE arrow_to=? AND state='SENT' AND deleted=0`
- **Archived**: `WHERE arrow_to=? AND is_archived=1` (conversation-level)

## Usage

### To Delete an ACK Conversation

```bash
curl -X DELETE "http://localhost:8080/api/conversations/{id}?desk_id={desk_id}"
```

### What Happens

1. All mivs in the conversation for that desk get `deleted = 1`
2. Conversation disappears from all baskets (IN, PENDING, SENT)
3. Other party's conversation unaffected (they have separate miv copies)
4. Data preserved in database for audit/recovery

## Testing Checklist

- [x] Backend compiles without errors
- [x] Database schema updated with deleted column
- [x] Performance index created
- [x] All queries filter by deleted=0
- [x] Delete endpoint added and compiles
- [ ] Test: Create conversation, verify appears in basket
- [ ] Test: Mark conversation as read, verify moves to correct basket
- [ ] Test: Send ACK, verify archives for both parties
- [ ] Test: Delete ACK, verify conversation disappears from baskets
- [ ] Test: Verify other party's conversation unaffected after delete
- [ ] Test: Query performance with index

## Performance Considerations

### Index Strategy

The compound index `(arrow_to, state, deleted)` supports:

- Fast lookups by desk ID
- Efficient filtering by state
- Quick exclusion of deleted mivs

### Query Performance

- Basket queries are now simple indexed lookups
- No complex joins or subqueries needed
- Frontend doesn't need to filter results

## Future Enhancements

1. **Undelete functionality**: Set `deleted = 0` to restore conversations
2. **Permanent deletion**: Clean up old deleted mivs after X days
3. **Soft delete timestamp**: Track when conversation was deleted
4. **Populate other_desk_id**: Could simplify some conversation queries
5. **Add desk_id column**: Would eliminate need for arrow_to in some cases

## Migration Path

### For Existing Databases

The schema change is backwards compatible:

- Default value is `0` (not deleted)
- All existing mivs appear as not deleted
- No data migration needed

### For New Databases

The schema.sql file includes the deleted column and index definition.

## Key Benefits

1. **Simplicity**: Clear, readable SQL queries
2. **Performance**: Indexed queries are fast
3. **Maintainability**: Logic centralized in database
4. **Data Safety**: Nothing actually deleted
5. **Clean Architecture**: Separation of concerns

## Notes

- The `deleted` flag operates at the miv level, not conversation level
- Each user has their own miv copies, so deletion is per-user
- Conversations use `is_archived` at conversation level (different concept)
- Deleted mivs are excluded from all queries except admin/audit functions
