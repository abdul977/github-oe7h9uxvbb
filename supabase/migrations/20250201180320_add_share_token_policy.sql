-- Add policy for accessing shared notes
CREATE POLICY "Allow access to shared notes"
  ON notes
  FOR SELECT
  TO authenticated
  USING (
    -- Allow access if sharing_token matches the query parameter
    sharing_token = current_setting('request.jwt.claims')::json->>'sharing_token'
    OR
    -- Maintain existing access for owners and collaborators
    auth.uid() = user_id
    OR
    collaborators::jsonb @> format('[{"user_id": "%s"}]', auth.uid())::jsonb
  );

-- Function to set sharing token
CREATE OR REPLACE FUNCTION set_sharing_token(share_token text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  PERFORM set_config('app.sharing_token', share_token, true);
END;
$$;

-- Update sharing token policy to use the new config
CREATE POLICY "Allow access to shared notes"
  ON notes
  FOR SELECT
  TO authenticated
  USING (
    -- Allow access if sharing_token matches
    sharing_token = current_setting('app.sharing_token', true)
    OR
    -- Maintain existing access for owners and collaborators
    auth.uid() = user_id
    OR
    collaborators::jsonb @> format('[{"user_id": "%s"}]', auth.uid())::jsonb
  );

-- Also allow access to note entries for shared notes
CREATE POLICY "Allow access to shared note entries"
  ON note_entries
  FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM notes
      WHERE notes.id = note_entries.note_id
      AND (
        notes.sharing_token = current_setting('app.sharing_token', true)
        OR notes.user_id = auth.uid()
        OR notes.collaborators::jsonb @> format('[{"user_id": "%s"}]', auth.uid())::jsonb
      )
    )
  );

-- Add trigger to set sharing token before SELECT operations
CREATE OR REPLACE FUNCTION trigger_set_sharing_token()
RETURNS trigger AS $$
BEGIN
  PERFORM set_sharing_token();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_sharing_token_trigger ON notes;
CREATE TRIGGER set_sharing_token_trigger
  BEFORE SELECT ON notes
  FOR EACH STATEMENT
  EXECUTE FUNCTION trigger_set_sharing_token();