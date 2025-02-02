/*
  # Fix Invitation Parameters Order

  Updates the accept_invitation function to use explicitly named parameters
  to prevent PostgREST from reordering them incorrectly.
*/

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
  -- Get invitation details
  SELECT note_id, permission, email INTO v_note_id, v_permission, v_email
  FROM invitations
  WHERE id = in_invitation_id
    AND accepted_at IS NULL
    AND expires_at > now();

  -- Check if invitation exists and is valid
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Invalid or expired invitation';
  END IF;

  -- Check if user email matches invitation using profiles
  IF v_email != (SELECT email FROM profiles WHERE id = in_user_id) THEN
    RAISE EXCEPTION 'Email mismatch';
  END IF;

  -- Update note collaborators
  UPDATE notes
  SET collaborators = COALESCE(collaborators, '[]'::jsonb) ||
    jsonb_build_object(
      'user_id', in_user_id,
      'permission', v_permission,
      'joined_at', now()
    )::jsonb
  WHERE id = v_note_id;

  -- Mark invitation as accepted
  UPDATE invitations
  SET accepted_at = now()
  WHERE id = in_invitation_id;

  RETURN true;
END;
$$;