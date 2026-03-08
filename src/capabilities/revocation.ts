export interface TokenRevocationRegistry {
  revoke(tokenId: string): void;
  isRevoked(tokenId: string): boolean;
  revokeAll(): void;
  readonly size: number;
}

export function createRevocationRegistry(): TokenRevocationRegistry {
  const revoked = new Set<string>();

  return Object.freeze({
    revoke(tokenId: string): void {
      revoked.add(tokenId);
    },
    isRevoked(tokenId: string): boolean {
      return revoked.has(tokenId);
    },
    revokeAll(): void {
      revoked.clear();
    },
    get size(): number {
      return revoked.size;
    },
  });
}
