-- Fix security issues: Remove public access from sensitive tables

-- 1. Revoke all permissions from anon role on profiles table
REVOKE ALL ON public.profiles FROM anon;
REVOKE ALL ON public.profiles FROM authenticated;

-- Grant only necessary permissions to authenticated users
GRANT SELECT, INSERT, UPDATE ON public.profiles TO authenticated;

-- 2. Revoke all permissions from anon role on documents table
REVOKE ALL ON public.documents FROM anon;
REVOKE ALL ON public.documents FROM authenticated;

-- Grant necessary permissions to authenticated users
GRANT SELECT, INSERT, UPDATE, DELETE ON public.documents TO authenticated;

-- 3. Revoke all permissions from anon role on user_roles table
REVOKE ALL ON public.user_roles FROM anon;
REVOKE ALL ON public.user_roles FROM authenticated;

-- Grant necessary permissions to authenticated users
GRANT SELECT ON public.user_roles TO authenticated;
-- Only admins can manage roles via RLS policy