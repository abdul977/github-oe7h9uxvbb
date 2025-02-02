import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { inviteCollaborator, generateShareLink, UserLookupResult } from '@/lib/collaborators';
import { UserLookup } from '@/components/UserLookup';
import { Copy, Share2, Link as LinkIcon, Loader2 } from 'lucide-react';

interface ShareButtonProps {
  noteId: string;
  currentUserId: string;
}

export function ShareButton({ noteId, currentUserId }: ShareButtonProps) {
  const [permission, setPermission] = useState<'view' | 'edit'>('view');
  const [shareLink, setShareLink] = useState<string>('');
  const [isGeneratingLink, setIsGeneratingLink] = useState(false);
  const [selectedUser, setSelectedUser] = useState<UserLookupResult | null>(null);
  const { toast } = useToast();

  const handleInvite = async () => {
    if (!selectedUser) {
      toast({
        title: 'Invalid Input',
        description: 'Please select a user to invite',
        variant: 'destructive'
      });
      return;
    }

    try {
      const success = await inviteCollaborator(noteId, {
        email: selectedUser.email,
        permission
      });

      if (success) {
        toast({
          title: 'Collaborator Invited',
          description: `${selectedUser.display_name || selectedUser.email} has been invited with ${permission} access`,
          variant: 'default'
        });
        setSelectedUser(null);
      } else {
        toast({
          title: 'Invitation Failed',
          description: 'Unable to invite collaborator. They may already have access.',
          variant: 'destructive'
        });
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'An unexpected error occurred',
        variant: 'destructive'
      });
    }
  };

  const handleGenerateShareLink = async () => {
    setIsGeneratingLink(true);
    try {
      const { url, error } = await generateShareLink(noteId);
      
      if (error || !url) {
        throw error || new Error('Failed to generate share link');
      }

      setShareLink(url);
      
      toast({
        title: 'Share Link Generated',
        description: 'The share link has been generated successfully',
        variant: 'default'
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to generate share link',
        variant: 'destructive'
      });
    } finally {
      setIsGeneratingLink(false);
    }
  };

  const handleCopyShareLink = async () => {
    if (!shareLink) {
      await handleGenerateShareLink();
    }
    
    try {
      await navigator.clipboard.writeText(shareLink);
      toast({
        title: 'Share Link Copied',
        description: 'The share link has been copied to your clipboard',
        variant: 'default'
      });
    } catch (error) {
      toast({
        title: 'Copy Failed',
        description: 'Unable to copy share link',
        variant: 'destructive'
      });
    }
  };

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button 
          variant="outline" 
          size="icon"
          className="bg-white/10 hover:bg-white/20 transition-colors"
        >
          <Share2 className="h-4 w-4 text-white" />
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-xl font-bold">Share Note</DialogTitle>
          <DialogDescription>
            Invite collaborators or generate a shareable link for this note
          </DialogDescription>
        </DialogHeader>
        
        <div className="space-y-6">
          {/* Invite Collaborator Section */}
          <div className="space-y-4">
            <h3 className="text-sm font-medium">Invite Collaborator</h3>
            <div className="space-y-4">
              <UserLookup 
                onUserSelect={setSelectedUser}
                placeholder="Search for user by email, name, or UID"
              />

              {selectedUser && (
                <div className="text-sm space-y-1 p-2 bg-secondary/50 rounded-md">
                  <p className="font-medium text-secondary-foreground">
                    {selectedUser.display_name || 'User Found'}
                  </p>
                  <p className="text-muted-foreground">Email: {selectedUser.email}</p>
                </div>
              )}

              <Select 
                value={permission}
                onValueChange={(value: 'view' | 'edit') => setPermission(value)}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select Permission" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="view">View</SelectItem>
                  <SelectItem value="edit">Edit</SelectItem>
                </SelectContent>
              </Select>

              <Button 
                onClick={handleInvite} 
                className="w-full"
                disabled={!selectedUser}
              >
                Send Invitation
              </Button>
            </div>
          </div>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-background px-2 text-muted-foreground">
                Or share via link
              </span>
            </div>
          </div>

          {/* Share Link Section */}
          <div className="space-y-4">
            <h3 className="text-sm font-medium">Share Link</h3>
            <div className="flex space-x-2">
              <Input
                value={shareLink}
                placeholder="Generate a share link..."
                readOnly
                className="flex-1"
              />
              <Button
                variant="secondary"
                className="shrink-0"
                onClick={handleGenerateShareLink}
                disabled={isGeneratingLink}
              >
                {isGeneratingLink ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    <LinkIcon className="h-4 w-4 mr-2" />
                    Generate
                  </>
                )}
              </Button>
            </div>
            <Button 
              variant="outline" 
              className="w-full" 
              onClick={handleCopyShareLink}
              disabled={isGeneratingLink}
            >
              <Copy className="mr-2 h-4 w-4" />
              Copy Share Link
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}