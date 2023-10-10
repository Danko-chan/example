import User from "../models/User.js";
import bcrypt from "bcryptjs";
import asyncHandler from "../middleware/asyncHandler.js";
import logger from "../utils/logger.js";
import jwt from "../utils/jwt.js"
import crypto, { randomBytes } from 'crypto'


    //User login
    const login = asyncHandler(async (req, res) => {
        const { email, password } = req.body;
   
        //Check if user exists
        const user = await User.findOne({ email });
        if(!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        //Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials'});
        }
        //Generate JWT token
        const payload = {
            user: {
                id: user.id,
            },
        };

        // Create a session object
        const session = {
            username: user.username,
            authStatus: true,
        };

        // Serialize the session object to JSON
        const sessionData = JSON.stringify(session);

        // Encrypt the session data
        const encryptionKey = process.env.SESSION_KEY; 
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
        let encryptedSessionData = cipher.update(sessionData, 'utf8', 'base64');
        encryptedSessionData += cipher.final('base64');

        // Set the encrypted session data as a cookie
        res.cookie('user_session', encryptedSessionData, {
            httpOnly: false,
            secure: false,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,  // Set session expiry to 24 hours from now
            path: '/',
        });

        // Encode the IV as a hexadecimal string and set it as a separate cookie
        const ivHex = iv.toString('hex');
        res.cookie('user_session_iv', ivHex, {
            httpOnly: false,
            secure: false, // Set to true if using HTTPS
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
            path: '/',
        });

       user.userSession = encryptedSessionData;

       const sessionExpiry = new Date();
       sessionExpiry.setHours(sessionExpiry.getHours() + 24); // Set session expiry to 24 hours from now
       user.userSessionExpiry = sessionExpiry;

       await user.save();

        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h'}, (err, token) =>{
            if(err) throw err;

            // Set the JWT token as an HttpOnly cookie
            res.cookie('authToken', token, {
            httpOnly: true,
            secure: false, // Set this to true if using HTTPS
            sameSite: 'strict', 
            maxAge: 24 * 60 * 60 * 1000, // Cookie expiration time (24 hours in milliseconds)
            path: '/', 
            });          
          
            res.json({message:'Login successful'});
            logger.info('login success');
        })
    });

    const logout = asyncHandler(async (req, res) => {

        const user = req.user; 
        
        if (!req.user) {
            return res.status(401).json({ error: 'Not authorized' });
        }
        user.userSession = null;
        user.userSessionExpiry = null;
        await user.save();

        // Clear cookies
        res.clearCookie('authToken', { path: '/' });
        res.clearCookie('user_session', { path: '/' });
        res.json({ message: 'Logged out successfully'});
      });

    export { register, login, logout};
    //authController.js

//new file Athentication.js
    import jwt from "jsonwebtoken";
import asyncHandler from "./asyncHandler.js";
import User from "../models/User.js";
import logger from "../utils/logger.js"

//Middleware to protect routes (requires a valid JWT)
const protect = asyncHandler(async (req, res, next) => {
    
    const token = req.cookies.authToken;
    if (!token) {
        res.status(401).json({ error: 'Not authorized, no token' });
      }
    try {
           
        //Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        logger.info('verified token');

        req.user = await User.findById(decoded.user.id);
        logger.info('found user by token');      
        next();
            
    } catch (error) {
        logger.info(error);
        res.status(401).json({ error: 'Not authorized, token failed' });
    }
    

})

export default protect;
// middleware which is executed before authcontroller to get req.body and token verification

// So what i want to do the session data that is username and authstatus i want to send it to the client on login 
//which will be stored in cookies which will not be httpOnly (could be accessed through js)

// i dont want to send username directly without encoding because i dont know whats the secure way to do it so i am
// encryprting it and then sending it to the client side but in doing i am encountering problem in decrypting.
