# User Profiles Implementation

## Context

The application needs to maintain user profile information that extends beyond the basic authentication data stored in `auth.users`. This includes display names and user-specific settings while ensuring proper access control and data consistency.

## Decision

We implemented a `profiles` table with Row Level Security (RLS) that automatically creates profile records when users sign up.

### Database Schema

```sql
CREATE TABLE profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  first_name text,
  last_name text,
  updated_at timestamptz DEFAULT timezone('utc'::text, now())
);

-- Automatic timestamp management
CREATE FUNCTION handle_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  new.updated_at = timezone('utc'::text, now());
  RETURN new;
END;
$$;

CREATE TRIGGER on_profile_updated
  BEFORE UPDATE ON profiles
  FOR EACH ROW EXECUTE PROCEDURE handle_updated_at();

-- Profile creation from user metadata
CREATE FUNCTION handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  INSERT INTO profiles (id, first_name, last_name)
  VALUES (
    new.id,
    new.raw_user_meta_data ->> 'first_name',
    new.raw_user_meta_data ->> 'last_name'
  );
  RETURN new;
END;
$$;
```

### Security Model

- RLS is enabled on the profiles table
- Users can only view and update their own profiles (strict RLS policies)
- Profile records are automatically created via database trigger when users sign up
- User metadata (first_name, last_name) is extracted from auth.users metadata during creation
- Automatic timestamp management for tracking profile updates

### TypeScript Integration

The profiles table is strongly typed using TypeScript interfaces:

```typescript
profiles: {
  Row: {
    id: string
    first_name: string | null
    last_name: string | null
    updated_at: string
  }
  Insert: {
    id: string
    first_name?: string | null
    last_name?: string | null
    updated_at?: string
  }
  Update: {
    id?: string
    first_name?: string | null
    last_name?: string | null
    updated_at?: string
  }
}
```

### Supabase API Usage

Common operations:

```typescript
// Read profile
const { data: profile } = await supabase
  .from('profiles')
  .select('*')
  .eq('id', userId)
  .single()

// Update profile
const { error } = await supabase
  .from('profiles')
  .update({ 
    first_name: 'New Name',
    updated_at: new Date().toISOString()
  })
  .eq('id', userId)

// Subscribe to profile changes
const channel = supabase.channel('custom-update-channel')
  .on(
    'postgres_changes',
    { event: 'UPDATE', schema: 'public', table: 'profiles' },
    (payload) => {
      console.log('Profile updated:', payload)
    }
  )
  .subscribe()
```

## Consequences

### Positive

- Automatic profile creation ensures data consistency
- Row Level Security enforces proper access control
- TypeScript integration provides compile-time type safety
- Real-time subscriptions enable immediate UI updates on profile changes

### Negative

- Additional database table to maintain
- Need to handle edge cases around profile creation timing
- Must maintain TypeScript types in sync with database schema

## Notes

- Profile data is publicly readable but privately writable
- The `updated_at` field tracks last modification time
- Direct foreign key to `auth.users` ensures referential integrity
- Real-time subscriptions should be used judiciously to avoid unnecessary updates