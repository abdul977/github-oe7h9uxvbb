# Fix Invitation Parameters Order

## Context

We've encountered an issue where PostgREST is expecting parameters for the `accept_invitation` function in a different order than defined. The function is defined with parameters (invitation_id, user_id), but PostgREST expects (current_user_id, invitation_id).

## Current Implementation

The function is defined in migrations:

```sql
CREATE OR REPLACE FUNCTION accept_invitation(invitation_id uuid, user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
```

The frontend calls it correctly with named parameters:

```typescript
await supabase.rpc('accept_invitation', {
  invitation_id: invitationId,
  user_id: user.id
});
```

## Problem

Even though the frontend uses named parameters, PostgREST is reordering them based on its own parameter inference, causing the error:

```
{
  code: 'PGRST202', 
  details: 'Searched for the function public.accept_invitation...r, but no matches were found in the schema cache.',
  hint: 'Perhaps you meant to call the function public.accept_invitation(current_user_id, invitation_id)',
  message: 'Could not find the function public.accept_invitation(invitation_id, user_id) in the schema cache'
}
```

## Solution

Create a new migration that updates the function definition to explicitly name the parameters in the function signature:

```sql
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
```

The key changes are:
1. Adding the `in_` prefix to parameter names to make them explicit and avoid any confusion
2. Using the prefixed names consistently inside the function body

## Next Steps

1. Switch to Code mode to create and apply the new migration
2. Test the function to ensure parameter ordering is now correctly handled

## Impact

This change:
- Fixes the parameter ordering issue without changing the underlying logic
- Makes the code more maintainable by explicitly naming parameters
- Ensures consistent behavior across PostgREST versions
- Requires no changes to the frontend code since it already uses named parameters