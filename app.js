// app.js

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const session = require('express-session');
// const bcrypt = require('bcrypt'); // Kommentert ut, men STERKT ANBEFALT å bruke! npm install bcrypt

const app = express();
const port = 3000;

// Middleware
app.use(express.json()); // To parse JSON bodies from frontend (used by /api/* routes)
app.use(express.urlencoded({ extended: true })); // To parse URL-encoded data from HTML forms

// Session management
// Requires a secret key to sign session cookies
app.use(session({
    secret: 'din_super_hemmelige_nokkel_med_minst_20_tegn', // REPLACE WITH A STRONG, UNIQUE KEY!
    resave: false, // Prevents session from being saved again if it hasn't changed
    saveUninitialized: false, // Prevents an empty session from being saved
    cookie: {
        secure: false, // Set to 'true' in production with HTTPS
        httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
        maxAge: 1000 * 60 * 60 * 24 // 24-hour session lifetime
    }
}));

// Connect to SQLite database
const dbPath = path.join(__dirname, 'ekmamen25.db'); // Ensure correct path to the database
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to the database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Run database schema if it hasn't been done already.
        // This should normally only be run once during initial setup.
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS Users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE
            )`);
            db.run(`CREATE TABLE IF NOT EXISTS Computers (
                computer_id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_number TEXT NOT NULL UNIQUE,
                brand TEXT NOT NULL,
                model TEXT,
                location TEXT,
                registered_by_user_id INTEGER,
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (registered_by_user_id) REFERENCES Users(user_id)
            )`);
            console.log('Tables Users and Computers checked/created.');
        });
    }
});

// Static files: 'public' directory is for content accessible to everyone (CSS, images, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// Routes for HTML pages to be served
// These serve the specific HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'view', 'index.html'));
});

app.get('/login', (req, res) => {
    // If the user is already logged in, redirect to privat.html
    if (req.session.userId) {
        return res.redirect('/privat');
    }
    res.sendFile(path.join(__dirname, 'view', 'login.html'));
});

app.get('/ny-bruker', isAuthenticated, (req, res) => {
    // If the user is already logged in, redirect to privat.html
  
    res.sendFile(path.join(__dirname, 'view', 'ny-bruker.html'));
});

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next(); // User is authenticated, continue to next middleware/route
    } else {
        // If not authenticated, redirect to the login page.
        // For API calls (like from privat.html), send 401 status.
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
             res.status(401).json({ message: 'Not authenticated. Please log in.' });
        } else {
            res.redirect('/login');
        }
    }
}

// Route for the protected page
app.get('/privat', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'view', 'privat.html'));
});


// ------ POST Routes from HTML forms (No /api/ prefix for these) ------

// POST /ny-bruker (Handles new user registration)
app.post('/ny-bruker', (req, res) => {
    const { navn, epost, passord } = req.body;

    if (!navn || !epost || !passord) {
        // In a real application, you would render the page again with an error message
        return res.status(400).send('All fields are required.');
    }

    // ##################################################################################################
    // IMPORTANT SECURITY NOTE:
    // The password MUST be hashed before being stored in the database! Use a library like 'bcrypt'.
    // Example (after 'npm install bcrypt'):
    // const hashedPassword = bcrypt.hashSync(passord, 10);
    // ##################################################################################################
    const hashedPassword = passord; // DO NOT USE IN PRODUCTION! Replace with bcrypt hash

    db.run('INSERT INTO Users (username, email, password) VALUES (?, ?, ?)',
        [navn, epost, hashedPassword], // 'navn' maps to 'username' column
        function (err) {
            if (err) {
                console.error('Error during user registration:', err.message);
                if (err.message.includes('UNIQUE constraint failed')) {
                    // In a real application, you would render the page again with an error message
                    return res.status(409).send('Username or email is already taken.');
                }
                return res.status(500).send('Internal server error during registration.');
            }
            // Upon successful registration, redirect to the login page
            res.redirect('/login?registered=true'); // Add query param for optional message in login
        }
    );
});

// POST /login (Handles login)
app.post('/login', (req, res) => {
    const { epost, passord } = req.body;

    if (!epost || !passord) {
        return res.status(400).send('Email and password are required.');
    }

    db.get('SELECT user_id, username, email, password FROM Users WHERE email = ?', [epost], (err, user) => {
        if (err) {
            console.error('Error during login:', err.message);
            return res.status(500).send('Internal server error.');
        }
        if (!user) {
            // If user not found, redirect back to login with error
            return res.status(401).send('Invalid email or password.');
        }

        // ##################################################################################################
        // IMPORTANT SECURITY NOTE:
        // Compare the hashed password! Use 'bcrypt.compareSync(passord, user.password)'.
        // ##################################################################################################
        if (passord === user.password) { // DO NOT USE IN PRODUCTION WITH PLAINTEXT!
            req.session.userId = user.user_id;
            req.session.username = user.username; // Store username in session
            req.session.email = user.email; // Store email in session
            return res.redirect('/privat'); // Redirect to the protected page
        } else {
            return res.status(401).send('Invalid email or password.');
        }
    });
});

// ------ API Routes for AJAX calls from frontend (used by JavaScript on privat.html) ------

// POST /api/logout
app.post('/api/logout', isAuthenticated, (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ message: 'Could not log out.' });
        }
        // Send an OK status. Frontend will handle redirection.
        res.status(200).json({ message: 'Logout successful.' });
    });
});

// GET /api/user-info (Protected route to fetch logged-in user info for JS)
app.get('/api/user-info', isAuthenticated, (req, res) => {
    // req.session.userId and req.session.username are set upon login
    if (req.session.userId) {
        res.status(200).json({ userId: req.session.userId, username: req.session.username, email: req.session.email });
    } else {
        // This should theoretically not happen if isAuthenticated works
        res.status(401).json({ message: 'No user is logged in.' });
    }
});


// POST /api/computers (Register new computer - PROTECTED ROUTE)
app.post('/api/computers', isAuthenticated, (req, res) => {
    const { serial_number, brand, model, location } = req.body;
    const registered_by_user_id = req.session.userId; // Get user ID from session

    if (!serial_number || !brand) {
        return res.status(400).json({ message: 'Serial number and brand are required.' });
    }

    db.run(
        'INSERT INTO Computers (serial_number, brand, model, location, registered_by_user_id) VALUES (?, ?, ?, ?, ?)',
        [serial_number, brand, model, location, registered_by_user_id],
        function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ message: 'Serial number already exists.' });
                }
                console.error('Error registering computer:', err.message);
                return res.status(500).json({ message: 'Internal server error during computer registration.' });
            }
            res.status(201).json({ message: 'Computer registered!', computerId: this.lastID });
        }
    );
});

// GET /api/computers (Fetch all registered computers - PROTECTED ROUTE)
app.get('/api/computers', isAuthenticated, (req, res) => {
    // Join with Users table to display username
    const query = `
        SELECT c.*, u.username as registered_by_username
        FROM Computers c
        JOIN Users u ON c.registered_by_user_id = u.user_id
        ORDER BY c.registration_date DESC;
    `;
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Error fetching computers:', err.message);
            return res.status(500).json({ message: 'Internal server error fetching computers.' });
        }
        res.status(200).json(rows);
    });
});

// PUT /api/computers/:id (Update a computer - PROTECTED ROUTE)
app.put('/api/computers/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const { serial_number, brand, model, location } = req.body;

    if (!serial_number || !brand) {
        return res.status(400).json({ message: 'Serial number and brand are required for update.' });
    }

    db.run(
        'UPDATE Computers SET serial_number = ?, brand = ?, model = ?, location = ? WHERE computer_id = ?',
        [serial_number, brand, model, location, id],
        function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ message: 'Serial number already exists for another computer.' });
                }
                console.error('Error updating computer:', err.message);
                return res.status(500).json({ message: 'Internal server error during computer update.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ message: 'Computer not found or no changes made.' });
            }
            res.status(200).json({ message: 'Computer updated successfully!' });
        }
    );
});

// DELETE /api/computers/:id (Delete a computer - PROTECTED ROUTE)
app.delete('/api/computers/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;

    db.run('DELETE FROM Computers WHERE computer_id = ?', [id], function (err) {
        if (err) {
            console.error('Error deleting computer:', err.message);
            return res.status(500).json({ message: 'Internal server error during computer deletion.' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ message: 'Computer not found.' });
        }
        res.status(200).json({ message: 'Computer deleted successfully!' });
    });
});


// Handle undefined routes (404)
app.use((req, res, next) => {
    res.status(404).send("Sorry, this page does not exist!");
});

// Start the server
app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
    console.log(`To start:`);
    console.log(`  Register new user: http://localhost:${port}/ny-bruker`);
    console.log(`  Log in: http://localhost:${port}/login`);
});
