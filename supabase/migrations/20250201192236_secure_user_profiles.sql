-- Create profiles table
create table public.profiles (
  id uuid not null references auth.users on delete cascade,
  first_name text,
  last_name text,
  updated_at timestamp with time zone default timezone('utc'::text, now()),
  
  primary key (id)
);

-- Enable RLS
alter table public.profiles enable row level security;

-- Create policy to allow users to view only their own profile
create policy "Users can view own profile"
  on public.profiles for select
  using ( auth.uid() = id );

-- Create policy to allow users to update only their own profile  
create policy "Users can update own profile"
  on public.profiles for update
  using ( auth.uid() = id );

-- Create trigger function for handling new user signup
create function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, first_name, last_name)
  values (
    new.id,
    new.raw_user_meta_data ->> 'first_name',
    new.raw_user_meta_data ->> 'last_name'
  );
  return new;
end;
$$;

-- Create trigger to automatically create profile for new users
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Create function to update updated_at timestamp
create function public.handle_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = timezone('utc'::text, now());
  return new;
end;
$$;

-- Create trigger for updating timestamp
create trigger on_profile_updated
  before update on public.profiles
  for each row execute procedure public.handle_updated_at();