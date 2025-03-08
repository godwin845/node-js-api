import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import mongoose, { model, Schema } from 'mongoose';

const app = express();

// Parsing json
app.use(express.json());
app.use(cors());

// Database configuration
mongoose.connect('mongodb://localhost:27017/login-authentication')
    .then(() => console.log('MongoDB Connected'))
    .catch(() => console.error('Connection error'));

// Model
const userSchema = new Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = model('User', userSchema);

// Controller

app.get('/', async (req, res) => {
    try {
        const fetchAllUsers = await User.find();
        res.status(200).json({ fetchAllUsers });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users!', error: error.message });
    }
});

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        res.status(400).json({ message: 'These fields are required!' });
    }

    try {
        const existingUser = await User.findOne({ email });

        if (existingUser) throw new Error("Email already exists!");

        const hashPassword = await bcrypt.hash(password, 10);
        const users = new User({ name, email, password: hashPassword });
        await users.save();

        res.status(200).json({ message: 'User registered successfully!' });

    } catch (error) {
        res.status(500).json({ message: 'Server error!', error: error.message });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        res.status(401).json({ message: 'These fields are required!' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) throw new Error("No email id found!");

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) throw new Error("Email or password is incorrect!");

        res.status(200).json({ message: 'Login successful!' });

    } catch (error) {
        res.status(500).json({ message: 'Server error!', error: error.message });
    }
});

app.put('/:id', async (req, res) => {
    const { id } = req.params;
    const { name, email, password } = req.body;

    try {
        const user = await User.findById(id);

        if (!user) {
            return res.status(404).json({ message: 'User not found!' });
        }

        if (email && email !== user.email) {
            const existingUser = await User.findOne({ email });

            if (existingUser) {
                return res.status(404).json({ message: 'Email id already in use!' });
            }

            user.email = email;
        }

        if (name) {
            user.name = name;
        }

        if (password) {
            user.password = await bcrypt.hash(password, 10);
        }

        await user.save();
        res.status(200).json({ message: 'Updated successfully!' });

    } catch (error) {
        res.status(500).json({ message: 'Server error!' });
    }
});

app.delete('/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const deleteUser = await User.findByIdAndDelete(id);

        if (!deleteUser) {
            return res.status(404).json({ message: 'User not found!' });
        }

        res.status(200).json({ message: 'Deleted successfully!' });

    } catch (error) {
        res.status(500).json({ message: 'Server error!' });
    }
});

app.listen(5000, () => {
    console.log(`Server running on http://localhost:${5000}`);
});