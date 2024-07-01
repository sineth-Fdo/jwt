import bcrypt from 'bcrypt';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import db from './db.js';
import { createTokens, validateToken } from './JWT.js';
import { User } from './model/user.js';


const app = express();
app.use(cookieParser())
app.use(cors());
app.use(bodyParser.json());
const PORT = 3000;
db();



app.post('/register',(req,res) => {
    
    const {username,password,role} = req.body;
    bcrypt.hash(password,10).then((hash) => {
        User.create({
            username: username,
            password: hash,
            role: role,
        }).then(() => {
            res.json('User Registered');
        
        }).catch((err) => {
            res.json(err.message).status(400);
        })
    })
    
})




app.post('/login', async (req,res) => {
    
    const { username , password } = req.body;

    const user = await User.findOne({username: username});

    if (!user) res.status(400).json({error: "User Doesn't Exist"});

    const dbPassword = user.password;
    bcrypt.compare(password, dbPassword).then((match) => {
        if (!match) {
            res.status(400)
            .json({error: "Wrong Username Or Password"});
        }else {
            const accessToken = createTokens(user);
        
    
            res.json(accessToken);
        }

    })

})

app.post('/profile',validateToken("user"),(req,res) => {
    res.json({
        details: "This is the profile data",
    });
})
app.post('/adminprofile',validateToken("admin"),(req,res) => {
    res.json({
        details: "This is the admin profile data",
    });
})

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});


