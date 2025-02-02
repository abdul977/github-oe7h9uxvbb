/*
  # Fix Database Permissions and Queries

  1. Changes
    - Add table aliases to queries to resolve ambiguous column references
    - Grant necessary permissions for users table
    - Update RLS policies with proper table aliases
    - Add missing indexes for performance

  2. Security
    - Maintain RLS while fixing permission issues
    - Add proper user table access for authenticated users
*/

-- Grant necessary permissions for users table
GRANT SELECT ON auth.users TO authenticated;

-- Drop existing policies to recreate them with proper table aliases
DROP POLICY IF EXISTS "Users can view their own notes" ON notes;
DROP POLICY IF EXISTS "Users can view note entries" ON note_entries;
DROP POLICY IF EXISTS "Users can update note entries" ON note_entries;
DROP POLICY IF EXISTS "Users can view invitations" ON invitations;

-- Recreate policies with proper table aliases
CREATE POLICY "Users can view their own notes"
  ON notes
  FOR SELECT
  TO authenticated
  USING (
    notes.user_id = auth.uid() OR 
    notes.collaborators::jsonb @> format('[{"user_id": "%s"}]', auth.uid())::jsonb
  );

CREATE POLICY "Users can view note entries"
  ON note_entries ne
  FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM notes n
      WHERE n.id = ne.note_id 
      AND (n.user_id = auth.uid() OR n.collaborators::jsonb @> format('[{"user_id": "%s"}]', auth.uid())::jsonb)
    )
  );

CREATE POLICY "Users can update note entries"
  ON note_entries ne
  FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM notes n
      WHERE n.id = ne.note_id 
      AND (n.user_id = auth.uid() OR n.collaborators::jsonb @> format('[{"user_id": "%s", "permission": "edit"}]', auth.uid())::jsonb)
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM notes n
      WHERE n.id = ne.note_id 
      AND (n.user_id = auth.uid() OR n.collaborators::jsonb @> format('[{"user_id": "%s", "permission": "edit"}]', auth.uid())::jsonb)
    )
  );

CREATE POLICY "Users can view invitations"
  ON invitations i
  FOR SELECT
  TO authenticated
  USING (
    i.email = (
      SELECT email 
      FROM auth.users 
      WHERE id = auth.uid()
    )
    OR
    EXISTS (
      SELECT 1 
      FROM notes n
      WHERE n.id = i.note_id 
      AND n.user_id = auth.uid()
    )
  );

-- Add indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
CREATE INDEX IF NOT EXISTS idx_note_entries_note_id ON note_entries(note_id);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);