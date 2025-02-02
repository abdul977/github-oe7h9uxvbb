import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { NoteEditor } from '@/components/NoteEditor';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/hooks/use-auth';
import { validateShareToken } from '@/lib/collaborators';

const NotePage = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user } = useAuth();
  const [note, setNote] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const location = window.location;
  const isSharedRoute = location.pathname.startsWith('/share/');
  const searchParams = new URLSearchParams(location.search);
  const shareToken = searchParams.get('token');
  
  useEffect(() => {
    const fetchNote = async () => {
      try {
        let data, error;

        // If it's a shared route, set the sharing token parameter
        if (isSharedRoute && shareToken) {
          try {
            await supabase.rpc('set_sharing_token', {
              share_token: shareToken
            });
          } catch (rpcError) {
            console.error('Error setting share token:', rpcError);
            toast({
              title: 'Error',
              description: 'Failed to validate share link',
              variant: 'destructive'
            });
            navigate('/');
            return;
          }
        }

        // Fetch the note and its entries
        ({ data, error } = await supabase
          .from('notes')
          .select(`
            id,
            title,
            user_id,
            created_at,
            updated_at,
            collaborators,
            sharing_token,
            entries:note_entries(
              content,
              entry_order
            )
          `)
          .eq('id', id)
          .order('entry_order', { foreignTable: 'note_entries' })
          .single());

        // If we have entries, concatenate their content
        if (data?.entries) {
          data.content = data.entries
            .sort((a: any, b: any) => a.entry_order - b.entry_order)
            .map((entry: any) => entry.content)
            .join('\n\n');
          delete data.entries;
        }

        if (error) {
          console.error('Supabase error details:', error);
          throw new Error(`Failed to fetch note: ${error.message}`);
        }

        if (!data) {
          navigate('/not-found');
          return;
        }

        // For shared routes, validate the share token
        if (isSharedRoute) {
          if (!shareToken) {
            toast({
              title: 'Invalid Share Link',
              description: 'No share token provided',
              variant: 'destructive'
            });
            navigate('/');
            return;
          }

          try {
            const isValidShare = await validateShareToken(id, shareToken);
            if (!isValidShare) {
              toast({
                title: 'Invalid Share Link',
                description: 'This share link is invalid or has expired',
                variant: 'destructive'
              });
              navigate('/');
              return;
            }
          } catch (validationError) {
            console.error('Share token validation error:', validationError);
            toast({
              title: 'Error',
              description: 'Failed to validate share link',
              variant: 'destructive'
            });
            navigate('/');
            return;
          }
        } else {
          // Check if user has access to this note
          const isOwner = data.user_id === user?.id;
          const isCollaborator = data.collaborators?.some(
            (c: any) => c.user_id === user?.id
          );

          if (!isOwner && !isCollaborator) {
            toast({
              title: 'Access Denied',
              description: 'You do not have permission to view this note',
              variant: 'destructive'
            });
            navigate('/');
            return;
          }
        }

        setNote(data);
      } catch (error) {
        console.error('Error fetching note:', error);
        toast({
          title: 'Error',
          description: 'Failed to load note',
          variant: 'destructive'
        });
        navigate('/');
      } finally {
        setLoading(false);
      }
    };

    if (id) {
      fetchNote();
    }
  }, [id, navigate, toast, user?.id]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500"></div>
      </div>
    );
  }

  if (!note) {
    return null;
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <NoteEditor
        note={note}
        open={true}
        onOpenChange={() => navigate('/')}
        onSave={() => {}}
        currentUserId={user?.id || ''}
        userPermission={
          isSharedRoute ? 'view' :
          note?.user_id === user?.id ? 'edit' :
          note?.collaborators?.find((c: any) => c.user_id === user?.id)?.permission || 'view'
        }
      />
    </div>
  );
};

export default NotePage;