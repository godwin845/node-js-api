import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

interface AuthenticationRequest extends Request {
    user?: any;
}

export const authenticate = (req: AuthenticationRequest, res:Response, next: NextFunction): void => {
    const token = req.header('Authorization')?.replace("Bearer ", "");

    if (!token) {
        res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token as string, process.env.JWT_SECRET as string);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Invalid token', error);
        res.status(500).json({ message: 'Invalid or expired token' });
    }
};