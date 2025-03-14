import express, { Application, NextFunction, Request, Response } from 'express';
import cors from 'cors';
import mongoose, { Document } from 'mongoose';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

dotenv.config();

const app: Application = express();

const HOST = 'localhost';
const PORT = 5000;

app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI as string)
    .then(() => {
        console.log('MongoDB is connected!');
    })
    .catch((error: Error) => {
        console.error('Connection error:', error.message);
    });

interface IUser extends Document {
    username: string;
    email: string;
    password: string;
}

const userSchema = new mongoose.Schema<IUser>({
    username: String,
    email: String,
    password: String,
});

const User = mongoose.model<IUser>('User', userSchema);


interface AuthenticationRequest {
    header: any;
    user?: any; 
}

const authenticate = (req: AuthenticationRequest, res: Response, next: NextFunction):void => {
    const token = req.header("Authorization")?.replace('Bearer ', '');
    
    if (!token) {
        res.status(401).json({ message: "No token provided!" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(500).json({ message: "Invalid or expired token!" });
    }
};


app.get('/', authenticate, async (req: Request, res: Response) => {
    try {
        const fetchAllUsers = await User.find();
        res.status(200).json({ fetchAllUsers });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users!' });
    }
});

app.post('/register', async (req: Request, res: Response) => {
    const { username, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });

        if (existingUser) throw new Error('Email already exists!');

        const hashPassword = await bcrypt.hash(password, 10);
        const users = new User({ username, email, password: hashPassword });
        await users.save();

        res.status(200).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Registration failed!' });
    }
});

app.post('/login', async (req: Request, res: Response) => {
    const { email, password } = req.body;

    try {
        const users = await User.findOne({ email });
        if (!users) throw new Error('Email not found!');

        const isMatch = await bcrypt.compare(password, users.password);
        if (!isMatch) throw new Error('Email or password is incorrect!');

        const token = jwt.sign({ userId: users._id, email: users.email }, process.env.JWT_SECRET as string);
        res.status(200).json({ message: 'Login successful!', token });
    } catch (error) {
        res.status(500).json({ message: 'Email or password is incorrect!' });
    }
});

// PUT Route (Update user info)
app.put('/:id', async (req: Request, res: Response): Promise<void> => {
    const { id } = req.params;
    const { username, email, password } = req.body;

    try {
        const user = await User.findById(id);

        if (!user) {
            res.status(404).json({ message: 'User not found!' });
            return;
        }

        // Check if the email is already used by another user
        if (email && email !== user.email) {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                res.status(400).json({ message: 'Email is already taken!' });
            }
        }

        if (password) {
            user.password = await bcrypt.hash(password, 10);
        }

        user.username = username || user.username;
        user.email = email || user.email;

        await user.save();
        res.status(200).json({ message: 'User updated successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to update user!' });
    }
});

// PATCH Route (Partial update of user info)
app.patch('/:id', async (req: Request, res: Response): Promise<void> => {
    const { id } = req.params;
    const { username, email, password } = req.body;

    try {
        const user = await User.findById(id);

        if (!user) {
            res.status(404).json({ message: 'User not found!' });
            return;
        }

        // Check if the email is already used by another user
        if (email && email !== user.email) {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                res.status(400).json({ message: 'Email is already taken!' });
                return;
            }
        }

        if (password) {
            user.password = await bcrypt.hash(password, 10);
        }

        user.username = username || user.username;
        user.email = email || user.email;

        await user.save();
        res.status(200).json({ message: 'User updated successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to update user!' });
    }
});

// DELETE Route (Delete user)
app.delete('/:id', async (req: Request, res: Response): Promise<void> => {
    const { id } = req.params;

    try {
        const deleteUser = await User.findByIdAndDelete(id);
        if (!deleteUser) {
            res.status(404).json({ message: 'User not found!' });
        }
        res.status(200).json({ message: 'User deleted successfully!', deleteUser });
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete user!' });
    }
});

app.listen(PORT, HOST, () => {
    console.log(`Server is running on port http://${HOST}:${PORT}`);
});