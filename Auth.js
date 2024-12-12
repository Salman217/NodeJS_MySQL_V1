const jwt = require('jsonwebtoken');

const JWT_SECRET = 'MovieSecret';


const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });
};

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};


module.exports = {generateToken,authenticateToken,JWT_SECRET};