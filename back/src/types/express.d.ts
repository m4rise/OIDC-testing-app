import express from 'express';

declare global {
  namespace Express {
    interface User {
      id: string;
      nni: string;
      email: string;
      firstName: string;
      lastName: string;
      fullName: string;
      roles: string[];
      currentRole: string;
      permissions: string[];
      isActive: boolean;
      createdAt: Date;
      lastLoginAt: Date | null;
      updatedAt: Date;
      tempJwtExpiry?: number;
    }
  }
}