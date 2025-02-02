/*
  # Add Profiles Table
  
  1. Changes
    - Create profiles table linked to auth.users
    - Add RLS policies for profiles
    - Create profile automatically when user signs up
  
  2. Security
    - Enable RLS
    - Add proper policies for profile access
*/

-- Create profiles table
CREATE TABLE IF NOT EXISTS profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email text NOT NULL,
  display_name text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- Enable RLS
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Create profiles policies
CREATE POLICY "Public profiles are viewable by everyone"
  ON profiles
  FOR SELECT
  USING (true);

CREATE POLICY "Users can update their own profile"
  ON profiles
  FOR UPDATE
  USING (auth.uid() = id);

-- Create function to auto-create profile on user signup
CREATE OR REPLACE FUNCTION create_profile_for_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email)
  VALUES (NEW.id, NEW.email);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger to auto-create profile
DROP TRIGGER IF EXISTS create_profile_on_signup ON auth.users;
CREATE TRIGGER create_profile_on_signup
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION create_profile_for_user();

-- Grant necessary permissions
GRANT ALL ON profiles TO authenticated;

-- Add index for better query performance
CREATE INDEX IF NOT EXISTS idx_profiles_email ON profiles(email);

-- Update invitations to check against profiles
DROP POLICY IF EXISTS "Users can view invitations" ON invitations;
CREATE POLICY "Users can view invitations"
  ON invitations i
  FOR SELECT
  TO authenticated
  USING (
    i.email = (
      SELECT email
      FROM profiles
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

-- Update accept_invitation function to use profiles
CREATE OR REPLACE FUNCTION accept_invitation(invitation_id uuid, user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_note_id uuid;
  v_permission text;
  v_email text;
BEGIN
  -- Get invitation details
  SELECT note_id, permission, email INTO v_note_id, v_permission, v_email
  FROM invitations
  WHERE id = invitation_id
    AND accepted_at IS NULL
    AND expires_at > now();

  -- Check if invitation exists and is valid
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Invalid or expired invitation';
  END IF;

  -- Check if user email matches invitation using profiles
  IF v_email != (SELECT email FROM profiles WHERE id = user_id) THEN
    RAISE EXCEPTION 'Email mismatch';
  END IF;

  -- Update note collaborators
  UPDATE notes
  SET collaborators = COALESCE(collaborators, '[]'::jsonb) ||
    jsonb_build_object(
      'user_id', user_id,
      'permission', v_permission,
      'joined_at', now()
    )::jsonb
  WHERE id = v_note_id;

  -- Mark invitation as accepted
  UPDATE invitations
  SET accepted_at = now()
  WHERE id = invitation_id;

  RETURN true;
END;
$$;