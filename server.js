require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const port = 5000;

// Configuration of the MySQL database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));

// Database connection
db.connect((err) => {
    if (err) {
        throw err;
    }
    console.log('Connected to the MySQL database');
});


// Handling POST requests from the registration form
app.post('/api/register', bodyParser.json(), async (req, res) => {
    const { schoolId, name, lastName, login, password, email, role, status } = req.body;

    // Validation
    const regex = /^[a-zA-Z0-9]+$/;
    const regexWithPL = /^[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ]+$/;
    const numberRegex = /^\d+$/;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    // School ID
    if(schoolId.length !== 10 || !numberRegex.test(schoolId)) {
        res.status(400).json({ message: 'bad_school' });
    }

    // First name
    if(name.length < 3 || name.length > 50 || !regexWithPL.test(name)) {
        res.status(400).json({ message: 'bad_data' });
    }

    // Last name
    if(lastName.length < 3 || lastName.length > 50 || !regexWithPL.test(lastName)) {
        res.status(400).json({ message: 'bad_data' });
    }

    // Email
    if(email.length > 100 || !emailRegex.test(email)) {
        res.status(400).json({ message: 'bad_data' });
    }

    // Login
    if(login.length < 3 || login.length > 50 || !regex.test(login)) {
        res.status(400).json({ message: 'bad_data' });
    }

    // Password
    if(password.length < 8 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
        res.status(400).json({ message: 'bad_data' });
    }


    // Checking if a user with the given login or email already exists in the database
    const checkLoginQuery = 'SELECT * FROM users WHERE login = ? OR email = ?';

    db.query(checkLoginQuery, [login, email], async (err, results) => {
        if (err) {
            res.status(500).json({ message: 'server_error' });
        } else if (results.length > 0) {
            if(results[0].login === login) {
                res.status(409).json({ message: 'login_exists' });
            } else {
                res.status(409).json({ message: 'email_exists' });
            }
        } else {
            // Checking if a school with the given ID exists in the database
            const checkSchoolQuery = 'SELECT * FROM schools WHERE school_id = ?';

            db.query(checkSchoolQuery, [schoolId], async (err, results) => {
                if (err) {
                    res.status(500).json({ message: 'server_error' });
                } else if (results.length > 0) {
                    try {
                        // Hashing the password using bcrypt
                        const hashedPassword = await bcrypt.hash(password, 10);

                        // Saving a new user to the database
                        const insertUserQuery = 'INSERT INTO users (first_name, last_name, login, password, email, school_id, role, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
                        db.query(insertUserQuery, [name, lastName, login, hashedPassword, email, schoolId, role, status], (err) => {
                            if (err) {
                                res.status(500).json({ message: 'server_error' });
                            } else {
                                res.json({ message: 'register_complete' });
                            }
                        });
                    } catch (error) {
                        res.status(500).json({ message: 'server_error' });
                    }
                } else {
                    res.status(400).json({ message: 'bad_school' });
                }
            });
        }
    });
});

// Handling POST requests from the login form
app.post('/api/login', bodyParser.json(), (req, res) => {
    const { login, password } = req.body;

    // Validation
    const regex = /^[a-zA-Z0-9]+$/;

    if(login.length < 3 || login.length > 50 || !regex.test(login) || password.length < 8 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
        res.status(400).json({ message: 'bad_data' });
    }
    

    // Searching for a user in the database based on login
    const getUserQuery = 'SELECT * FROM users WHERE login = ?';

    db.query(getUserQuery, [login], async (err, results) => {
        if (err) {
            console.log(err);
            res.status(500).json({ message: 'server_error' });
        } else if (results.length === 0) {
            res.status(401).json({ message: 'bad_data' });
        } else {
            try {
                const user = results[0];
                const passwordMatch = await bcrypt.compare(password, user.password);

                if (passwordMatch) {
                    // Setting session variables
                    req.session.loggedIn = true;
                    req.session.userId = user.id;
                    req.session.firstName = user.first_name;
                    req.session.lastName = user.last_name;
                    req.session.login = user.login;
                    req.session.email = user.email;
                    req.session.schoolId = user.school_id;
                    req.session.role = user.role;
                    req.session.photoURL = user.photo_url;
                    req.session.language = user.language;
                    req.session.theme = user.theme;
                    req.session.status = user.status;

                    res.json({ 
                        userId: req.session.userId,
                        firstName: req.session.firstName,
                        lastName: req.session.lastName,
                        login: req.session.login,
                        email: req.session.email,
                        schoolId: req.session.schoolId,
                        role: req.session.role,
                        photoURL: req.session.photoURL,
                        language: req.session.language,
                        theme: req.session.theme,
                        status: req.session.status
                    });
                } else {
                    res.status(401).json({ message: 'bad_data' });
                }
            } catch (error) {
                console.log(error);
                res.status(500).json({ message: 'server_error' });
            }
        }
    });
});

// Checking session variables
app.get('/api/checkSession', (req, res) => {
    if (req.session.loggedIn) {
        res.json({ 
            userId: req.session.userId,
            firstName: req.session.firstName,
            lastName: req.session.lastName,
            login: req.session.login,
            email: req.session.email,
            schoolId: req.session.schoolId,
            role: req.session.role,
            photoURL: req.session.photoURL,
            language: req.session.language,
            theme: req.session.theme,
            status: req.session.status
        });
    } else {
        res.json(null);
    }
});

// Handling logout request
app.get('/api/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        res.status(500).json({ message: 'server_error' });
      } else {
        res.json({ message: 'logout_success' });
      }
    });
});

// Closing the database connection after the application finishes its execution
process.on('SIGINT', () => {
    db.end((err) => {
        if (err) {
            console.log(err);
            process.exit(1);
        } else {
            console.log('Zamknięto połączenie z bazą danych MySQL');
            process.exit(0);
        }
    });
});

// Starting the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});