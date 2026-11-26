import { createContext, useContext, type ReactNode } from 'react';
import type { Entity, User } from './model';
import type { Rec } from './lib';

export interface Expiration { r: Rec; date: string; kind: 'Expiration' | 'Review' }
export type ModalSize = '' | 'wide' | 'small';

export interface AppCtx {
  user: User;
  records: Rec[];
  favorites: Rec[];
  scope: string;
  writable: boolean;
  admin: boolean;
  byId(id?: string): Rec | undefined;
  title(id?: string): string;
  ofType(type: string): Rec[];
  inScope(r: Rec): boolean;
  expirations(): Expiration[];
  reload(): Promise<void>;
  setUser(user: User): void;
  navigate(page: string): void;
  openDiagram(id: string): void;
  openDetail(id: string): Promise<void>;
  edit(type: Entity, id?: string, preset?: Partial<Rec>): void;
  modal(title: string, content: ReactNode, size?: ModalSize): void;
  close(): void;
  toast(message: string): void;
}

export const Ctx = createContext<AppCtx | null>(null);
export function useApp() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useApp must be used inside the workspace');
  return ctx;
}
