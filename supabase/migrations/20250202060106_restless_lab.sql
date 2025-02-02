/*
  # Complete Database Schema for Whimsical Idea Keeper

  1. Tables
    - profiles (user profiles)
    - notes (main notes table)
    - note_entries (note content entries)
    - invitations (collaboration invitations)
  
  2. Security
    - Row Level Security (RLS) policies for all tables
    - Secure functions for collaboration management
  
  3. Functions
    - User management triggers
    - Collaboration handling
    - Share token management
*/

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create profiles table
CREATE TABLE IF NOT EXISTS profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email text NOT NULL,
  first_name text,
  last_name text,
  display_name text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- Create notes table
CREATE TABLE IF NOT EXISTS notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  collaborators jsonb DEFAULT '[]',
  content_versions jsonb DEFAULT '[]',
  last_active_collaborators jsonb DEFAULT '{}',
  sharing_token text
);

-- Create note_entries table
CREATE TABLE IF NOT EXISTS note_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  note_id uuid REFERENCES notes(id) ON DELETE CASCADE,
  content text,
  audio_url text,
  entry_order integer NOT NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  created_by_email text,
  updated_by_email text
);

-- Create invitations table
CREATE TABLE IF NOT EXISTS invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  note_id uuid REFERENCES notes(id) ON DELETE CASCADE,
  email text NOT NULL,
  token text NOT NULL,
  permission text NOT NULL CHECK (permission IN ('view', 'edit')),
  invited_by uuid REFERENCES auth.users(id),
  expires_at timestamptz NOT NULL,
  created_at timestamptz DEFAULT now(),
  accepted_at timestamptz
);

-- Enable Row Level Security
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE note_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;

-- Create profile management functions
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  INSERT INTO public.profiles (id, email, first_name, last_name)
  VALUES (
    NEW.id,
    NEW.email,
    NEW.raw_user_meta_data->>'first_name',
    NEW.raw_user_meta_data->>'last_name'
  );
  RETURN NEW;
END;
$$;

-- Create trigger for new user profile creation
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- Create updated_at timestamp management
CREATE OR REPLACE FUNCTION handle_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = timezone('utc'::text, now());
  RETURN NEW;
END;
$$;

-- Create triggers for updated_at management
CREATE TRIGGER handle_profiles_updated_at
  BEFORE UPDATE ON profiles
  FOR EACH ROW EXECUTE FUNCTION handle_updated_at();

CREATE TRIGGER handle_notes_updated_at
  BEFORE UPDATE ON notes
  FOR EACH ROW EXECUTE FUNCTION handle_updated_at();

CREATE TRIGGER handle_note_entries_updated_at
  BEFORE UPDATE ON note_entries
  FOR EACH ROW EXECUTE FUNCTION handle_updated_at();

-- Create note entry user tracking function
CREATE OR REPLACE FUNCTION set_note_entry_user_email()
RETURNS TRIGGER AS $$
DECLARE
  v_email text;
BEGIN
  SELECT email INTO v_email
  FROM auth.users
  WHERE id = auth.uid();

  IF TG_OP = 'INSERT' THEN
    NEW.created_by_email = v_email;
    NEW.updated_by_email = v_email;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.content IS DISTINCT FROM OLD.content THEN
      NEW.updated_by_email = v_email;
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create triggers for note entry user tracking
CREATE TRIGGER set_note_entry_user_email_insert
  BEFORE INSERT ON note_entries
  FOR EACH ROW EXECUTE FUNCTION set_note_entry_user_email();

CREATE TRIGGER set_note_entry_user_email_update
  BEFORE UPDATE ON note_entries
  FOR EACH ROW EXECUTE FUNCTION set_note_entry_user_email();

-- Create invitation acceptance function
CREATE OR REPLACE FUNCTION accept_invitation(
  in_invitation_id uuid,
  in_user_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_note_id uuid;
  v_permission text;
  v_email text;
BEGIN
  SELECT note_id, permission, email INTO v_note_id, v_permission, v_email
  FROM invitations
  WHERE id = in_invitation_id
    AND accepted_at IS NULL
    AND expires_at > now();

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Invalid or expired invitation';
  END IF;

  IF v_email != (SELECT email FROM profiles WHERE id = in_user_id) THEN
    RAISE EXCEPTION 'Email mismatch';
  END IF;

  UPDATE notes
  SET collaborators = COALESCE(collaborators, '[]'::jsonb) ||
    jsonb_build_object(
      'user_id', in_user_id,
      'permission', v_permission,
      'joined_at', now()
    )::jsonb
  WHERE id = v_note_id;

  UPDATE invitations
  SET accepted_at = now()
  WHERE id = in_invitation_id;

  RETURN true;
END;
$$;

-- Create RLS Policies

-- Profiles policies
CREATE POLICY "Users can view own profile"
  ON profiles FOR SELECT
  USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
  ON profiles FOR UPDATE
  USING (auth.uid() = id);

-- Notes policies
CREATE POLICY "Users can create notes"
  ON notes FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can view their own notes"
  ON notes FOR SELECT
  TO authenticated
  USING (
    user_id = auth.uid() OR 
    collaborators::jsonb @> format('[{"user_id": "%s"}]', auth.uid())::jsonb OR
    sharing_token = current_setting('app.sharing_token', true)
  );

CREATE POLICY "Users can update their own notes"
  ON notes FOR UPDATE
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own notes"
  ON notes FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id);

-- Note entries policies
CREATE POLICY "Users can create note entries"
  ON note_entries FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND (user_id = auth.uid() OR collaborators::jsonb @> format('[{"user_id": "%s", "permission": "edit"}]', auth.uid())::jsonb)
    )
  );

CREATE POLICY "Users can view note entries"
  ON note_entries FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND (
        user_id = auth.uid() OR 
        collaborators::jsonb @> format('[{"user_id": "%s"}]', auth.uid())::jsonb OR
        sharing_token = current_setting('app.sharing_token', true)
      )
    )
  );

CREATE POLICY "Users can update note entries"
  ON note_entries FOR UPDATE
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

CREATE POLICY "Users can delete note entries"
  ON note_entries FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND (user_id = auth.uid() OR collaborators::jsonb @> format('[{"user_id": "%s", "permission": "edit"}]', auth.uid())::jsonb)
    )
  );

-- Invitations policies
CREATE POLICY "Users can create invitations for their notes"
  ON invitations FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND user_id = auth.uid()
    )
  );

CREATE POLICY "Users can view invitations"
  ON invitations FOR SELECT
  TO authenticated
  USING (
    email = (SELECT email FROM profiles WHERE id = auth.uid()) OR
    EXISTS (
      SELECT 1 FROM notes 
      WHERE id = note_id 
      AND user_id = auth.uid()
    )
  );

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
CREATE INDEX IF NOT EXISTS idx_notes_collaborators ON notes USING gin (collaborators);
CREATE INDEX IF NOT EXISTS idx_note_entries_note_id ON note_entries(note_id);
CREATE INDEX IF NOT EXISTS idx_note_entries_created_by_email ON note_entries(created_by_email);
CREATE INDEX IF NOT EXISTS idx_note_entries_updated_by_email ON note_entries(updated_by_email);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON profiles(email);

-- Grant necessary permissions
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO authenticated;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO authenticated;