import React, { useState, useEffect } from 'react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Loader2 } from 'lucide-react';
import { UserLookupResult, lookupUser } from '@/lib/collaborators';

interface UserLookupProps {
  onUserSelect: (user: UserLookupResult) => void;
  placeholder?: string;
}

export function UserLookup({ onUserSelect, placeholder = "Search by email, UID, or name" }: UserLookupProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [userResults, setUserResults] = useState<UserLookupResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const searchUsers = async () => {
      if (!searchTerm) {
        setUserResults([]);
        return;
      }

      setIsSearching(true);
      setError(null);

      try {
        const user = await lookupUser(searchTerm);
        if (user) {
          setUserResults([user]);
        } else {
          setUserResults([]);
        }
      } catch (err) {
        console.error('Error searching users:', err);
        setError('Failed to search users');
        setUserResults([]);
      } finally {
        setIsSearching(false);
      }
    };

    // Debounce the search
    const timeoutId = setTimeout(searchUsers, 300);
    return () => clearTimeout(timeoutId);
  }, [searchTerm]);

  return (
    <div className="space-y-4">
      <div className="relative">
        <Input
          type="text"
          placeholder={placeholder}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full"
        />
        {isSearching && (
          <div className="absolute right-2 top-1/2 transform -translate-y-1/2">
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          </div>
        )}
      </div>

      {error && (
        <p className="text-sm text-destructive">{error}</p>
      )}

      <div className="space-y-2">
        {userResults.map((user) => (
          <div
            key={user.id}
            className="flex items-center justify-between p-3 bg-secondary/50 rounded-lg hover:bg-secondary/70 transition-colors cursor-pointer"
            onClick={() => onUserSelect(user)}
          >
            <div className="space-y-1">
              <p className="font-medium text-secondary-foreground">
                {user.display_name || `${user.first_name || ''} ${user.last_name || ''}`.trim() || 'Unnamed User'}
              </p>
              <p className="text-sm text-muted-foreground">{user.email}</p>
              <p className="text-xs text-muted-foreground">ID: {user.id}</p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => {
                e.stopPropagation();
                onUserSelect(user);
              }}
            >
              Select
            </Button>
          </div>
        ))}
        {searchTerm && !isSearching && userResults.length === 0 && (
          <p className="text-sm text-muted-foreground text-center py-2">
            No users found
          </p>
        )}
      </div>
    </div>
  );
}