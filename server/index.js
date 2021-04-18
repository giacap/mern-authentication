const express = require('express')
const mongoose = require('mongoose')
const app = express()
require('dotenv').config()
const PORT = process.env.PORT
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const csrf = require('csurf')
const csrfProtection = csrf({ cookie: true })

//const cors = require('cors')
//app.use(cors())

app.use(express.json())


app.use(cookieParser())

//import model
const User = require('./models/User')
const Post = require('./models/Post')





//check current user
app.get('/user', (req, res) => {
    try {
        const token = req.cookies.jwt

        if(token){
            jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
                if(err){
                    return res.status(400).json({
                        success: false,
                        message: 'no current user'
                    })
                } else {
                    const user = await User.findById(decodedToken.id)
                    return res.status(200).json({
                        success: true,
                        currentUser: user.username
                    })
                }
            })
        } else {
            return res.status(400).json({
                success: false,
                message: 'no current user'
            })
        }
        
    } catch (err) {
        return res.status(500).json({
            success: false,
            error: 'server error'
        })
    }
})





//Verify if user is authenticated 
const requireAuth = (req, res, next) => {
    const token = req.cookies.jwt 

    if(token){
        jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
            if(err){
                res.redirect('/')
            } else {
                next()
            }
        })
    } else {
        res.redirect('/')
    }
}





//send csrf token to client
const sendCsrfToken = (req, res, next) => {
    const token = req.csrfToken()
    res.cookie('XSRF-TOKEN', token)
    next()
}



// serve front end

app.use(express.static(path.join(__dirname, '/..', 'client', 'build')))


app.get('/secretpage', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, '/..', 'client', 'build', 'index.html'))
})


app.get('/add', requireAuth, csrfProtection, sendCsrfToken, (req, res) => {
    res.sendFile(path.join(__dirname, '/..', 'client', 'build', 'index.html'))
})


app.get('/logout', (req, res) => {
    res.cookie('jwt', '', {maxAge: 1})
    res.redirect('/')
})


app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '/..', 'client', 'build', 'index.html'))
})








// connect to db and listen on port for connections
const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true,
        })
        console.log('connected to MongoDB')
        app.listen(PORT, () => console.log('server running on port ' + PORT))
    } catch (err) {
        console.log(`error: ${err.message}`)
        process.exit(1)
    }
}

connectDB()
//






// create a JWT
const createToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: 24 * 60 * 60
    })
}








// SIGN UP
app.post('/signup', async (req, res) => {

    const {username, password} = req.body

    try {
        const user = await User.create(req.body)

        //create the token and store it in a cookie
        const token = createToken(user._id)
        res.cookie('jwt', token, {
            httpOnly: true,
            secure: true,
            maxAge: 24 * 60 * 60 * 1000,
            sameSite: 'Lax'
        })

        return res.status(201).json({
            success: true,
            data: user
        })
        
        
        
    } catch (err) {
        if(err.name === 'ValidationError'){
            const messages = Object.values(err.errors).map( val => val.message)
            return res.status(404).json({
                success: false,
                error: messages
            })
        } else if(err.name === 'MongoError'){
            const user = err.keyValue.username
            return res.status(404).json({
                success: false,
                error: `${user} is already registered`
            })
        } else {
            return res.status(500).json({
                success: false,
                error: 'server error'
            })
        }
    }
})






// LOG IN
app.post('/login', async (req, res) => {
    
    const user = await User.findOne({username: req.body.username})
    if(!user) {
        return res.status(400).json({success: false, error: 'incorrect username'})
    }

    try {
        const auth = await bcrypt.compare(req.body.password, user.password)
        if(auth){
            const token = createToken(user._id)
            res.cookie('jwt', token, {
                httpOnly: true,
                secure: true,
                maxAge: 24 * 60 * 60 * 1000,
                sameSite: 'Lax'
            })
            return res.status(200).json({success: true})
        } else {
            return res.status(400).json({success: false, error: 'incorrect password'})
        }
    } catch (err) {
        return res.status(500).json({
            success: false,
            error: 'server error'
        })
    }
})






//test
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
//







//
const requireAuth2 = (req, res, next) => {
    const token = req.cookies.jwt 

    if(token){
        jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
            if(err){
                return res.send('not allowed')
            } else {
                next()
            }
        })
    } else {
        res.send('not allowed')
    }
}













app.post('/add', requireAuth2, csrfProtection, (req, res) => {
    const text = req.body.text
    const token = req.cookies.jwt

    try {
        
        jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
            if(err){
                console.log('FAIL: post non aggiunto')
                return res.status(400).json({success: false})
            } else {
                const post = await Post.create({authorId: decodedToken.id, text: text})
                console.log('SUCCESSO: posto aggiunto')
                return res.status(201).json({success: true, post: post})
            }
        })   

    } catch (err) {

        return res.status(500).json({
            success: false,
            message: 'error'
        }) 
    } 
})
