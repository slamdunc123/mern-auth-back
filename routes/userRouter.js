const router = require('express').Router();
const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const auth = require('../middleware/auth');
// user test route

router.get('/test', (req, res) => {
	res.send("Hello it's working");
});

// register user - public route
router.post('/register', async (req, res) => {
	try {
		let { email, password, passwordCheck, displayName } = req.body;

		// check validation
		if (!email || !password || !passwordCheck)
			return res
				.status(400)
				.json({ msg: 'Not all fields have been entered.' });
		if (password.length < 5)
			return res.status(400).json({
				msg: 'The password needs to be at least 5 characters long.',
			});
		if (password !== passwordCheck)
			return res.status(400).json({
				msg: 'Enter the same password twice for verification.',
			});

		// check for existing user
		const existingUser = await User.findOne({ email: email });
		if (existingUser)
			return res.status(400).json({
				msg: 'An account with this email already exists.',
			});

		// check for display name
		if (!displayName) displayName = email;

		// hash password and compare with one in database
		const salt = await bcrypt.genSalt();
		const passwordHash = await bcrypt.hash(password, salt);
		// console.log(passwordHash);

		// create and save new user
		const newUser = new User({
			email,
			password: passwordHash,
			displayName,
		});
		const savedUser = await newUser.save();
		res.json(savedUser);
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
});

// login user - public route
router.post('/login', async (req, res) => {
	try {
		const { email, password } = req.body;

		// check if email or password not entered
		if (!email || !password)
			return res
				.status(400)
				.json({ msg: 'Not all fields have been entered' });

		const user = await User.findOne({ email: email });

		// check if user exists
		if (!user)
			return res.status(400).json({
				msg: 'No account with this email has beed registered',
			});

		// check if password matches user password in database
		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch)
			return res.status(400).json({ msg: 'Invalid credentials' });

		// create validated user token and send info back to front end
		const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
		console.log(token);
		res.json({
			token,
			user: {
				id: user._id,
				displayName: user.displayName,
				email: user.email,
			},
		});
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
});

// delete logged in user - private route
router.delete('/delete', auth, async (req, res) => {
	// console.log(req.user);
	try {
		const deletedUser = await User.findByIdAndDelete(req.user);
		res.json(deletedUser);
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
});

// check token is valid route
router.post('/tokenIsValid', async (req, res) => {
	try {
		const token = req.header('x-auth-token');
		if (!token) return res.json(false);

		const verified = jwt.verify(token, process.env.JWT_SECRET);
		if (!verified) return res.json(false);

		const user = await User.findById(verified.id);
		if (!user) return res.json(false);

		return res.json(true);
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
});

// get current logged in user
router.get('/', auth, async (req, res) => {
	const user = await User.findById(req.user);
	res.json({
		displayName: user.displayName,
		id: user._id,
	});
});

module.exports = router;
