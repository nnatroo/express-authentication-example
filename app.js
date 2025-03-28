const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// Configure session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set secure: true in production with HTTPS
}));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Simple user storage (in production, use a database)
const USERS_FILE = 'users.json';

// Initialize users file if it doesn't exist
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, '[]');
}

// Helper functions for user management
function getUsers() {
    const data = fs.readFileSync(USERS_FILE);
    return JSON.parse(data);
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function findUserByEmail(email) {
    const users = getUsers();
    return users.find(user => user.email === email);
}

function createUser(email, password) {
    const users = getUsers();
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = { email, password: hashedPassword };
    users.push(newUser);
    saveUsers(users);
    return newUser;
}

// Middleware to check if user is authenticated
function requireAuth(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Routes
app.get('/', (req, res) => {
    res.render('home', { user: req.session.user });
});

app.get('/login', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const user = findUserByEmail(email);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.render('login', { error: 'Invalid email or password' });
    }

    req.session.user = { email: user.email };
    res.redirect('/dashboard');
});

app.get('/register', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('register', { error: null });
});

app.post('/register', (req, res) => {
    const { email, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.render('register', { error: 'Passwords do not match' });
    }

    if (findUserByEmail(email)) {
        return res.render('register', { error: 'Email already registered' });
    }

    createUser(email, password);
    req.session.user = { email };
    res.redirect('/dashboard');
});

app.get('/dashboard', requireAuth, (req, res) => {
    res.render('dashboard', { user: req.session.user });
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

const BLOGS_FILE = 'blogs.json';

if (!fs.existsSync(BLOGS_FILE)) {
    fs.writeFileSync(BLOGS_FILE, '[]');
}

function getBlogs() {
    return JSON.parse(fs.readFileSync(BLOGS_FILE));
}

function saveBlogs(blogs) {
    fs.writeFileSync(BLOGS_FILE, JSON.stringify(blogs, null, 2));
}


// Show all blogs
app.get('/blogs', (req, res) => {
    const blogs = getBlogs();
    res.render('blogs', { user: req.session.user, blogs });
});

// Show form to create a blog (only for logged-in users)
app.get('/blogs/new', requireAuth, (req, res) => {
    res.render('new_blog', { user: req.session.user, error: null });
});

// Show a single blog
app.get('/blogs/:id', (req, res) => {
    const blogs = getBlogs();
    const blog = blogs.find(b => b.id === req.params.id);
    if (!blog) {
        return res.status(404).send('Blog not found');
    }
    res.render('blog', { user: req.session.user, blog });
});


// Handle new blog submission
app.post('/blogs', requireAuth, (req, res) => {
    const { title, content } = req.body;
    if (!title || !content) {
        return res.render('new_blog', { user: req.session.user, error: 'Title and content required' });
    }

    const blogs = getBlogs();
    const newBlog = {
        id: String(Date.now()), // Simple ID generation
        title,
        content,
        author: req.session.user.email,
        date: new Date().toLocaleString(),
    };

    blogs.push(newBlog);
    saveBlogs(blogs);

    res.redirect('/blogs');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
