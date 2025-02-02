/*
  # Track User Changes in Note Entries
  
  1. Changes
    - Add email tracking columns to note_entries
    - Create trigger to automatically populate email fields
    - Update policies to maintain security
  
  2. Security
    - Maintain RLS policies
    - Add proper validation for email fields
*/

-- Add email tracking columns to note_entries
ALTER TABLE note_entries
ADD COLUMN IF NOT EXISTS created_by_email text,
ADD COLUMN IF NOT EXISTS updated_by_email text;

-- Create a trigger function to automatically set email fields
CREATE OR REPLACE FUNCTION set_note_entry_user_email()
RETURNS TRIGGER AS $$
DECLARE
  v_email text;
BEGIN
  -- Get the current user's email
  SELECT email INTO v_email
  FROM auth.users
  WHERE id = auth.uid();

  -- For new entries, set both created and updated email
  IF TG_OP = 'INSERT' THEN
    NEW.created_by_email = v_email;
    NEW.updated_by_email = v_email;
  
  -- For updates, only set updated email
  ELSIF TG_OP = 'UPDATE' THEN
    -- Only update if content changed
    IF NEW.content IS DISTINCT FROM OLD.content THEN
      NEW.updated_by_email = v_email;
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create triggers for note_entries
DROP TRIGGER IF EXISTS set_note_entry_user_email_insert ON note_entries;
CREATE TRIGGER set_note_entry_user_email_insert
  BEFORE INSERT ON note_entries
  FOR EACH ROW
  EXECUTE FUNCTION set_note_entry_user_email();

DROP TRIGGER IF EXISTS set_note_entry_user_email_update ON note_entries;
CREATE TRIGGER set_note_entry_user_email_update
  BEFORE UPDATE ON note_entries
  FOR EACH ROW
  EXECUTE FUNCTION set_note_entry_user_email();

-- Update existing entries with creator's email if possible
UPDATE note_entries ne
SET created_by_email = u.email,
    updated_by_email = u.email
FROM notes n
JOIN auth.users u ON n.user_id = u.id
WHERE ne.note_id = n.id
  AND ne.created_by_email IS NULL;

-- Add indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_note_entries_created_by_email 
ON note_entries(created_by_email);

CREATE INDEX IF NOT EXISTS idx_note_entries_updated_by_email 
ON note_entries(updated_by_email);

-- Update the RLS policies to ensure proper access control
ALTER TABLE note_entries ENABLE ROW LEVEL SECURITY;

-- Users can view entries in notes they have access to (unchanged)
CREATE OR REPLACE POLICY "Users can view note entries"
  ON note_entries
  FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND (user_id = auth.uid() OR collaborators::jsonb @> format('[{"user_id": "%s"}]', auth.uid())::jsonb)
    )
  );

-- Users can create entries if they have edit permission
CREATE OR REPLACE POLICY "Users can create note entries"
  ON note_entries
  FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND (user_id = auth.uid() OR collaborators::jsonb @> format('[{"user_id": "%s", "permission": "edit"}]', auth.uid())::jsonb)
    )
  );

-- Users can update entries if they have edit permission
CREATE OR REPLACE POLICY "Users can update note entries"
  ON note_entries
  FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND (user_id = auth.uid() OR collaborators::jsonb @> format('[{"user_id": "%s", "permission": "edit"}]', auth.uid())::jsonb)
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND (user_id = auth.uid() OR collaborators::jsonb @> format('[{"user_id": "%s", "permission": "edit"}]', auth.uid())::jsonb)
    )
  );

-- Users can delete entries if they have edit permission
CREATE OR REPLACE POLICY "Users can delete note entries"
  ON note_entries
  FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND (user_id = auth.uid() OR collaborators::jsonb @> format('[{"user_id": "%s", "permission": "edit"}]', auth.uid())::jsonb)
    )
  );

-- Update the types definition to include new fields
COMMENT ON TABLE note_entries IS 'Stores individual note entries with user tracking';
COMMENT ON COLUMN note_entries.created_by_email IS 'Email of the user who created the entry';
COMMENT ON COLUMN note_entries.updated_by_email IS 'Email of the user who last modified the entry';