-- Add first_name column to profiles table
ALTER TABLE profiles ADD COLUMN first_name text;

-- Update trigger function to include first_name from user metadata
CREATE OR REPLACE FUNCTION create_profile_for_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, first_name)
  VALUES (
    NEW.id,
    NEW.email,
    (NEW.raw_user_meta_data->>'first_name')
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;