const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');
const bcrypt = require('bcryptjs');
const User = require('./models/user')
const crypto = require('crypto')
const nodemailer = require('nodemailer')

require('dotenv').config();

const app = express()
const PORT = process.env.PORT || 3000

mongoose.connect(process.env.atlas_URL)
    .then(() => console.log('Connected....'))
    .catch(err => console.error(err))

app.use(express.urlencoded({ extended: false }))
app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))
app.use(express.static(path.join(__dirname, 'public')))

//session middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))

//passport middleware
app.use(passport.initialize())
app.use(passport.session())
app.use(flash())

//global variables for flahs messages.
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg')
    res.locals.error_msg = req.flash('error_msg')
    res.locals.error = req.flash('error')
    res.locals.user = req.user || null
    next()
})

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {

        const user = await User.findOne({ email: email })

        if (!user) {
            return done(null, false, { message: 'Email not registered' })
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if (isMatch) {
            return done(null, user)
        } else {
            return done(null, false, { message: 'Password incorrect' })
        }

    } catch (err) {
        return done(err)
    }
}))


passport.serializeUser((user, done) => done(null, user.id))
passport.deserializeUser(async (id, done) => {

    try {

        const user = await User.findById(id)
        done(null, user)
    } catch (err) { done(err, null); }

});

// --- Authentication Helper Function (Middleware) ---
function ensureAuthenticated(req, res, next) {

    if (req.isAuthenticated()) { return next() }
    req.flash('error_msg', 'Please log in to view that resource')
    res.redirect('/login')

}

//routes section.
app.get('/', (req, res) => res.render('index'))

app.get('/dashboard', ensureAuthenticated, (req, res) => res.render('dashboard', { user: req.user }))

app.get('/register', (req, res) => res.render('register'))

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        req.flash('success_msg', 'You are now registered and can log in');
        res.redirect('/login');
    } catch (err) {
        req.flash('error_msg', 'Error registering user. Try a different email/username.');
        res.redirect('/register');
    }
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
}));

app.get('/logout', (req, res) => {
    req.logout(function (err) {
        if (err) { return next(err); }
        req.flash('success_msg', 'You are logged out');
        res.redirect('/login');
    });
});

app.get('/forgot', (req, res) => res.render('forgot'));

app.post('/forgot', async (req, res) => {
    try {

        const token = crypto.randomBytes(20).toString('hex');
        const user = await User.findOne({ email: req.body.email });

        if (!user) {
            req.flash('error_msg', 'No account with that email address exists.');
            return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'Gmail', 
                auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        
        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL_USER,
            subject: 'Password Reset',
            text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                  'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                  process.env.APP_URL + '/reset/' + token + '\n\n' +
                  'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        };

        
        transporter.sendMail(mailOptions, (err) => {
            if (err) throw err;
            req.flash('success_msg', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
            res.redirect('/forgot');
        });

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'An error occurred while sending the email.');
        res.redirect('/forgot');
    }
});


app.get('/reset/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() } // Check if token is not expired
        });

        if (!user) {
            req.flash('error_msg', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }

        res.render('reset', { token: req.params.token });

    } catch (err) {
        req.flash('error_msg', 'An error occurred.');
        res.redirect('/forgot');
    }
});

// Handle Reset Password Submission (Set New Password)
app.post('/reset/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            req.flash('error_msg', 'Password reset token is invalid or has expired.');
            return res.redirect('/forgot');
        }

        if (req.body.password !== req.body.confirm) {
            req.flash('error_msg', 'Passwords do not match.');
            return res.redirect(`/reset/${req.params.token}`);
        }

        // Hash the new password and save it
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(req.body.password, salt);
        user.resetPasswordToken = undefined; // Invalidate the token
        user.resetPasswordExpires = undefined; // Invalidate the expiration

        await user.save();
        
        req.flash('success_msg', 'Success! Your password has been changed.');
        res.redirect('/login');

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'An error occurred during password reset.');
        res.redirect('/forgot');
    }
});


app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`))
