import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import mongoose, { model, Schema } from 'mongoose';

const app = express();

// Parsing json

app.use(express.json());
app.use(cors());

app.use(passport.initialize());

// Database configuration

mongoose.connect('mongodb://localhost:27017/login-authentication')
    .then(() => console.log('MongoDB Connected'))
    .catch(() => console.error('Connection error'));

// Model

const userSchema = new Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
})

const User = model('User', userSchema);

// JWT

const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'No token provided!' });
    }

    try {
        const decoded = jwt.verify(token, 'khsbakfsnkj');
        req.user = decoded;
        next()
    } catch (error) {
        return res.status(500).json({ message: 'Token invalid!', error: error.message });
    }
}

// Controller

app.get('/', async (req, res) => {
    try {
        const fetchAllUsers = await User.find();
        res.status(200).json({ fetchAllUsers });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users!', error: error.message });
    }
})


app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        res.status(400).json({ message: 'These fields are required!' });
    }

    try {
        const existingUser = await User.findOne({ email });

        if (existingUser) throw new Error("Email already exists");

        const hashPassword = await bcrypt.hash(password, 10);
        const users = new User({ name, email, password: hashPassword });
        await users.save();

        res.status(200).json({ message: 'User registered successfully!' });

    } catch (error) {

        res.status(500).json({ message: 'Server error!', error: error.message });
    }
});


app.post('/login', authenticate, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        res.status(401).json({ message: 'These fields are required!' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) throw new Error("No email id found!");

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) throw new Error("Email or password is incorrect!");

        const token = jwt.sign({ id: user._id }, 'khsbakfsnkj', { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successfull!', token });

    } catch (error) {

        res.status(500).json({ message: 'Server error!', error: error.message });
    }
});


// Google OAuth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    const token = jwt.sign({ id: req.user._id }, 'khsbakfsnkj', { expiresIn: '1h' });
    res.redirect(`http://localhost:3000/?token=${token}`);
});


app.listen(5000, () => {
    console.log(`Server running on http://localhost:${5000}`);
})